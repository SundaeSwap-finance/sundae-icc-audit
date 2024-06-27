package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	sundaecli "github.com/SundaeSwap-finance/sundae-go-utils/sundae-cli"
	"github.com/fatih/color"
	"github.com/fxamacker/cbor/v2"
	"github.com/savaki/bech32"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/blake2b"
)

const usage = "audit-icc-results"

var service = sundaecli.NewService(usage)

var opts struct {
	StakeSnapshot string
	Votes         string
}

func main() {
	flags := append(
		sundaecli.CommonFlags,
		sundaecli.StringFlag("votes", "the csv file with votes", &opts.Votes),
		sundaecli.StringFlag("stake-snapshot", "the csv file with the stake snapshot", &opts.StakeSnapshot),
	)
	app := sundaecli.App(
		service,
		action,
		flags...,
	)
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalln(err)
	}
}

type Vote struct {
	CreatedAt        time.Time
	PayloadTimestamp time.Time
	StakeAddress     string
	CoseKeyHex       string
	CoseSignatureHex string
	SignedTx         string
	Message          string
	Selections       []string
	VotingPower      uint64
}

// Extract the signing key from a COSE header cbor structure
func extractKey(coseKey string) ([]byte, error) {
	keyBytes, err := hex.DecodeString(coseKey)
	if err != nil {
		return nil, err
	}
	var cose map[int]interface{}
	if err := cbor.Unmarshal(keyBytes, &cose); err != nil {
		return nil, err
	}
	key, ok := cose[-2].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid cose key type")
	}
	return key, nil
}

// The raw application payload that was wrapped in a COSE envelope and signed
type VotePayload struct {
	// A list of the users votes, in order of preference
	Params []string `json:"params"`
	// The timestamp the vote was cast, to prevent replay attacks
	Timestamp uint64 `json:"timestamp"`
}

// The information captured by a COSE payload; doesn't serialize exactly
type CosePayload struct {
	Key          []byte
	Address      []byte
	HeaderBytes  []byte
	PayloadBytes []byte
	Payload      VotePayload
	Signature    []byte
}

// The exact signed payload that a user would have provided their signature for
type SignedPayload struct {
	_ struct{} `cbor:",toarray"`
	// Context, set to Signature1
	Context string
	// The bytes of the COSE headers, containing the algorithm, key, etc
	RawBodyHeaders []byte
	// Another source of COSE headers, always empty for these votes
	RawSignHeaders []byte
	// The raw application payload to be signed
	RawApplicationPayload []byte
}

// From the bytes collected by the summon platform, extract the CosePayload
func extractSignature(payload string) (CosePayload, error) {
	// This is the raw CBOr structure of what each vote looks like
	var cosePayloadRaw struct {
		_         struct{} `cbor:",toarray"`
		Headers   []byte
		Meta      cbor.RawMessage
		Payload   []byte
		Signature []byte
	}
	payloadBytes, err := hex.DecodeString(payload)
	if err != nil {
		return CosePayload{}, err
	}
	if err := cbor.Unmarshal(payloadBytes, &cosePayloadRaw); err != nil {
		return CosePayload{}, err
	}
	// The headers should include the algorithm, the signing key, and the address of the voter
	// In some cases, the key ID (Kid) is left off, or encoded as the key hash with header bytes instead
	var coseHeaders struct {
		Alg     int    `cbor:"1,keyasint"`
		Kid     []byte `cbor:"4,keyasint"`
		Address []byte `cbor:"address"`
	}
	if err := cbor.Unmarshal(cosePayloadRaw.Headers, &coseHeaders); err != nil {
		return CosePayload{}, err
	}

	var votePayload VotePayload
	if err := json.Unmarshal(cosePayloadRaw.Payload, &votePayload); err != nil {
		return CosePayload{}, err
	}
	return CosePayload{
		Key:          coseHeaders.Kid,
		Address:      coseHeaders.Address,
		HeaderBytes:  cosePayloadRaw.Headers,
		PayloadBytes: cosePayloadRaw.Payload,
		Payload:      votePayload,
		Signature:    cosePayloadRaw.Signature,
	}, nil
}

// Convert a CosePayload into the actual raw bytes that would have been signed by the user
func constructSignedPayloadBytes(cosePayload CosePayload) ([]byte, error) {
	signedPayload := SignedPayload{
		Context:               "Signature1",
		RawBodyHeaders:        cosePayload.HeaderBytes,
		RawSignHeaders:        []byte{},
		RawApplicationPayload: cosePayload.PayloadBytes,
	}
	return cbor.Marshal(signedPayload)
}

// Load a file containing the stake snapshot for any voters; A warning will be printed if the user isn't in this snapshot
// For the purposes of the ICC vote, I populated this file with the following query against an up to date cardano-db-sync instance
//
// select sa."view", es.amount from epoch_stake es left outer join stake_address sa on sa.id = es.addr_id where epoch_no = 491 and sa."view" in ( ... )
//
// with ... replaced by all of the staking keys present in the votes file
func loadStakeSnapshot(filename string) (map[string]uint64, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	stakeSnapshot := map[string]uint64{}
	rows, err := csv.NewReader(bytes.NewReader(file)).ReadAll()
	if err != nil {
		return nil, err
	}
	for idx, row := range rows {
		if idx == 0 {
			continue
		}
		stakeAddress := strings.Trim(row[0], " ")
		stake, err := strconv.ParseUint(strings.Trim(row[1], " "), 10, 64)
		if err != nil {
			return nil, err
		}
		stakeSnapshot[stakeAddress] = stake
	}
	return stakeSnapshot, nil
}

// Load and validate the vote CSV, with reference to a specific stake snapshot
func loadAndValidateVotes(filename string, stakeSnapshot map[string]uint64) (map[string]Vote, error) {
	// Read the file, and parse the raw CSV into a Vote structure that we can validate
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var votes []Vote
	rows, err := csv.NewReader(bytes.NewReader(file)).ReadAll()
	if err != nil {
		return nil, err
	}
	for idx, row := range rows {
		if idx == 0 {
			continue
		}
		time, err := time.Parse("2006-01-02 15:04:05", row[0])
		if err != nil {
			return nil, err
		}
		votingPower := uint64(0)
		if strings.Trim(row[12], " ") != "" {
			votingPower, err = strconv.ParseUint(strings.Trim(row[12], " "), 10, 64)
			if err != nil {
				return nil, err
			}
		}

		var selections []string
		done := false
		// Print out a warning if there are any gaps in the users votes, like Selection1,Selection3,Selection5
		for i := 6; i <= 11; i++ {
			if strings.Trim(row[i], " ") == "" {
				done = true
			} else {
				if done {
					fmt.Printf("Invalid vote; non-consecutive entries: %v\n", row[1])
				}
				selections = append(selections, row[i])
			}
		}

		vote := Vote{
			CreatedAt:        time,
			StakeAddress:     strings.Trim(row[1], " "),
			CoseKeyHex:       row[2],
			CoseSignatureHex: row[3],
			SignedTx:         row[4],
			Message:          row[5],
			Selections:       selections,
			VotingPower:      votingPower,
		}
		votes = append(votes, vote)
	}

	// Now, we can validate each vote; we'll be calculating a lot of blake2b-224 hashes, so get a new hasher ready
	hasher, err := blake2b.New(224/8, nil)
	if err != nil {
		return nil, err
	}

	// Some terminal printing niceties
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	ANOMALY := red("ANOMALY")

	fmt.Printf("%v votes in input file.\n", green(len(votes)))

	// Vote start and end dates
	// The start is the moment that the ICC tweeted the vote was open,
	// and the end is the moment the voting closed
	votingOpened, _ := time.Parse("2006-01-02 15:04:05", "2024-06-13 21:55:00")
	votingClosed, _ := time.Parse("2006-01-02 15:04:05", "2024-06-23 21:44:40")

	latestVotes := map[string]Vote{}
	duplicates := 0
	noVotes := 0
	for _, vote := range votes {
		// Check that the vote was cast in the correct voting window
		if vote.CreatedAt.Before(votingOpened) {
			fmt.Printf("%v: Vote received before opening time: %v\n", ANOMALY, vote.StakeAddress)
		}
		if vote.CreatedAt.After(votingClosed) {
			fmt.Printf("%v: Vote received after closing time: %v\n", ANOMALY, vote.StakeAddress)
		}

		// Votes can have no voting power, but if this is very large, it indicates a problem
		if vote.VotingPower == 0 {
			noVotes++
		}

		// If the vote doesn't have a balance in the snapshot, this is ok, but a large number of these could indicate a problem
		if _, ok := stakeSnapshot[vote.StakeAddress]; !ok {
			fmt.Printf("%v: Stake address missing voting power in the snapshot: %v\n", ANOMALY, vote.StakeAddress)
		}
		if vp, ok := stakeSnapshot[vote.StakeAddress]; ok && vp == 0 {
			fmt.Printf("%v: Stake address has zero voting power in the snapshot: %v\n", ANOMALY, vote.StakeAddress)
		}
		// If the vote in the CSV **disagrees** with the stake snapshot, this is a much bigger problem
		if stakeSnapshot[vote.StakeAddress] != vote.VotingPower {
			fmt.Printf("%v: Invalid voting power: %v\n", ANOMALY, vote.StakeAddress)
		}

		// Deconstruct the stake address into it's key hash
		hrp, stakeAddress, err := bech32.Decode(vote.StakeAddress)
		if err != nil {
			return nil, err
		}
		// We don't support voting with payment credentials, only stake credentials
		if hrp != "stake" {
			fmt.Printf("%v: Invalid stake address: %v\n", ANOMALY, vote.StakeAddress)
		}

		// Now, reconstruct the vote payload, either extracting it from the signed transaction, or from the CIP-8 COSE payload
		var votePayload VotePayload
		if vote.SignedTx != "" {
			// in-place deserialization of the relevant fields of the transaction
			var tx struct {
				_         struct{} `cbor:",toarray"`
				TxBody    cbor.RawMessage
				Witnesses map[int][]struct {
					_         struct{} `cbor:",toarray"`
					Key       []byte
					Signature []byte
				}
				Valid    cbor.RawMessage
				Metadata map[int]interface{}
			}
			txBytes, err := hex.DecodeString(vote.SignedTx)
			if err != nil {
				return nil, err
			}
			if err := cbor.Unmarshal(txBytes, &tx); err != nil {
				fmt.Printf("%v\n", vote.StakeAddress)
				return nil, err
			}

			// Calculate the transaction hash, so we can validate each signature
			txHash := blake2b.Sum256(tx.TxBody)
			signedByStakeKey := false
			for _, witness := range tx.Witnesses[0] {
				if !ed25519.Verify(witness.Key, txHash[:], witness.Signature) {
					fmt.Printf("%v: Invalid signature: %v\n", ANOMALY, vote.StakeAddress)
				}
				hasher.Reset()
				hasher.Write(witness.Key)
				// The tx doesn't have to *only* be signed by the stake key,
				// but one of the signatures should be from the stake address
				// Note we strip off the header byte and deal *just* with the stake key hash
				if bytes.Equal(stakeAddress[1:], hasher.Sum(nil)) {
					signedByStakeKey = true
				}
			}
			// If the transaction wasn't signed by the staking key, we effectively don't have a signature for this vote
			if !signedByStakeKey {
				fmt.Printf("%v: Not signed by stake key: %v\n", ANOMALY, vote.StakeAddress)
			}

			// The metadata format is a bit annoying and non-standard, so we attempt to reconstruct it from the
			// different formats here
			var mdStr string
			if str, ok := tx.Metadata[674].(string); ok {
				mdStr = str
			} else if strs, ok := tx.Metadata[674].([]interface{}); ok {
				for _, str := range strs {
					mdStr += str.(string)
				}
			} else if md_map, ok := tx.Metadata[0].(map[interface{}]interface{}); ok {
				// In some cases it's not stored as a string, just as a cbor object, so we deal with that here instead of setting mdStr
				for k, v := range md_map {
					if kk, ok := k.(uint64); ok && kk == 674 || kk == 678 {
						if kk == 678 {
							fmt.Printf("%v: Anomalous Metadata Tag, 678 instead of 674 %v\n", ANOMALY, vote.StakeAddress)
						}
						md_map = v.(map[interface{}]interface{})
						for k, v := range md_map {
							switch k.(string) {
							case "timestamp":
								votePayload.Timestamp = v.(uint64)
							case "params":
								ps := v.([]interface{})
								for _, p := range ps {
									votePayload.Params = append(votePayload.Params, p.(string))
								}
							}
						}
					}
				}
			} else {
				fmt.Printf("%v: Invalid metadata: %v %T\n", ANOMALY, vote.StakeAddress, tx.Metadata[674])
			}
			// If we have a metadata string (see the note above), we can parse it as json into the vote payload
			if mdStr != "" {
				if err := json.Unmarshal([]byte(mdStr), &votePayload); err != nil {
					fmt.Printf("%v: Invalid metadata: %v\n", ANOMALY, vote.StakeAddress)
				}
			}
		} else {
			// We should grab the key from the header
			csvKey, err := extractKey(vote.CoseKeyHex)
			if err != nil {
				return nil, err
			}
			// and the signature
			payload, err := extractSignature(vote.CoseSignatureHex)
			if err != nil {
				return nil, err
			}

			// The stake address we decoded from the CSV should *always* match the one in the signed payload
			if !bytes.Equal(stakeAddress, payload.Address) {
				fmt.Printf("%v: Address mismatch: %v\n", ANOMALY, vote.StakeAddress)
			}

			// Calculate the key hash from of the public key
			var csvKeyHash []byte
			hasher.Reset()
			hasher.Write(csvKey)
			csvKeyHash = hasher.Sum(nil)

			// There are three different formats of the key / payload, depending on the wallet
			// In all cases, the hash of the key reported in the CSV should match the key hash from the stake address reported in the CSV
			if !bytes.Equal(csvKeyHash, stakeAddress[1:]) {
				fmt.Printf("%v: Key hash mismatch: %v\n", ANOMALY, vote.StakeAddress)
			}
			// And then one of the following must be true
			valid := false
			// 1. No key is encoded in the payload
			if len(payload.Key) == 0 {
				valid = true
			} else {
				// 2. The raw key is encoded in the payload, and should match the one reported in the CSV
				// 3. The stake address bytes (e1 + keyHash) is encoded in the payload, and it matches the key reported in the CSV, and the stake address
				if bytes.Equal(payload.Key, csvKey) {
					valid = true
				} else if bytes.Equal(payload.Key, stakeAddress) {
					valid = true
				}
			}
			if !valid {
				fmt.Printf("%v: Key mismatch: %v\n", ANOMALY, vote.StakeAddress)
			}

			// Reconstruct the bytes that the user would have signed, according to the CIP-8 COSE standard
			signedPayloadBytes, err := constructSignedPayloadBytes(payload)
			if err != nil {
				return nil, err
			}

			// And then verify the ed25519 signature
			if !ed25519.Verify(csvKey, signedPayloadBytes, payload.Signature) {
				fmt.Printf("%v: Invalid signature: %v\n", ANOMALY, vote.StakeAddress)
			}

			// Then save the vote payload, so we can do further validation below
			votePayload = payload.Payload
		}

		// Regardless of whether the payload was in the transaction or a COSE envelope, there are further validations we can do
		payloadDate := time.Unix(int64(votePayload.Timestamp/1000), 1e6*int64(votePayload.Timestamp)%1000)
		// Check that the timestamp from the signed data matches the server time collected in the CSV, or at least "decently" close
		if payloadDate.Sub(vote.CreatedAt) < -20*time.Minute || payloadDate.Sub(vote.CreatedAt) > 20*time.Minute {
			fmt.Printf("%v: Timestamp mismatch: %v - Timestamps differ by %v. CSV: %v, Payload: %v\n", ANOMALY, vote.StakeAddress, payloadDate.Sub(vote.CreatedAt), vote.CreatedAt, payloadDate)
		}

		// Track this, so we can compare by payload timestamp or by server timestamp
		vote.PayloadTimestamp = payloadDate

		// If they didn't vote for anyone, that's suspicious
		if len(votePayload.Params) == 0 {
			fmt.Printf("%v: Vote with no selection: %v\n", ANOMALY, vote.StakeAddress)
		}
		// And if they voted for more than 6 people, that's also suspicious
		if len(votePayload.Params) > 6 {
			fmt.Printf("%v: Vote with more than 6 selections: %v\n", ANOMALY, vote.StakeAddress)
		}
		// The two arrays should be identical: from the payload, and from the CSV
		if !reflect.DeepEqual(votePayload.Params, vote.Selections) {
			fmt.Printf("%v: Selection mismatch: %v - expected %v - found %v\n", ANOMALY, vote.StakeAddress, vote.Selections, votePayload.Params)
		}

		// If we've already seen a vote from this staking key, we may need to keep the newer one
		if previous, ok := latestVotes[vote.StakeAddress]; ok {
			duplicates++
			// Here, we use the server time, but you can easily switch this to the payload timestamp
			// In the ICC vote, this had no impact on the outcome
			if vote.CreatedAt.Equal(previous.CreatedAt) {
				fmt.Printf("%v: Duplicate vote with same timestamp: %v\n", ANOMALY, vote.StakeAddress)
			} else if vote.CreatedAt.After(previous.CreatedAt) {
				// to be sure it had no impact, check that the ordering of the payload timestamp also agrees
				if vote.PayloadTimestamp.Before(previous.PayloadTimestamp) {
					fmt.Printf("%v: Ordering by timestamps disagrees: %v\n", ANOMALY, vote.StakeAddress)
				}
				latestVotes[vote.StakeAddress] = vote
			}
		} else {
			latestVotes[vote.StakeAddress] = vote
		}
	}
	// If we had duplicates, warn about them
	if duplicates > 0 {
		fmt.Printf("%v: %v Duplicate votes - %v distinct votes\n", ANOMALY, duplicates, len(latestVotes))
	}
	// If we had people with no voting power, warn about it
	if noVotes > 0 {
		fmt.Printf("%v: %v Votes with zero voting power\n", ANOMALY, noVotes)
	}
	return latestVotes, nil
}

// Print out a round of IRV voting, in order, with some nice coloring
func printSelection(selections map[string]uint64) {
	green := color.New(color.FgGreen).SprintFunc()
	var pairs []struct {
		selection string
		votes     uint64
	}
	for selection, votes := range selections {
		pairs = append(pairs, struct {
			selection string
			votes     uint64
		}{selection, votes})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].votes > pairs[j].votes })
	for _, pair := range pairs {
		fmt.Printf("  %-50v: %25d\n", green(pair.selection), pair.votes)
	}
}

// Calculate an IRV runoff by counting everyones first vote, eliminating the candidate with the lowest votes,
// and switching anyone who voted for them to their second choice, etc.
func calculateRunoff(votes map[string]Vote) {
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	var selections map[string]uint64
	eliminated := map[string]bool{}
	round := 1
	for {
		selections = map[string]uint64{}
		// Pick the first non-eliminated vote
		for _, vote := range votes {
			selection := ""
			for _, s := range vote.Selections {
				if !eliminated[s] {
					selection = s
					break
				}
			}
			if selection == "" {
				// All of their candidates were eliminated
				continue
			}
			selections[selection] += vote.VotingPower
		}

		// If we have narrowed it down to 6 parties, we have our 3 winners and 3 alternates
		if len(selections) <= 6 {
			break
		}

		fmt.Printf("Round %v (%v candidates remaining)\n", green(round), len(selections))
		printSelection(selections)

		// Find the lowest entry, and mark them as eliminated
		var pairs []struct {
			selection string
			votes     uint64
		}
		for selection, votes := range selections {
			pairs = append(pairs, struct {
				selection string
				votes     uint64
			}{selection, votes})
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].votes < pairs[j].votes })

		fmt.Println()
		fmt.Printf("Eliminating %v\n", red(pairs[0].selection))
		eliminated[pairs[0].selection] = true

		fmt.Printf("================\n")
		round += 1
	}
	// Print the final results
	fmt.Printf("Final Results:\n")
	printSelection(selections)
}

func action(ctx *cli.Context) error {
	stakeSnapshot, err := loadStakeSnapshot(opts.StakeSnapshot)
	if err != nil {
		return err
	}
	votes, err := loadAndValidateVotes(opts.Votes, stakeSnapshot)
	if err != nil {
		return err
	}

	calculateRunoff(votes)
	return nil
}
