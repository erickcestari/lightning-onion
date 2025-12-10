package sphinx

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

const (
	routeBlindingTestFileName      = "testdata/route-blinding-test.json"
	onionRouteBlindingTestFileName = "testdata/onion-route-blinding-test.json"
)

// TestBuildBlindedRoute tests BuildBlindedRoute and decryptBlindedHopData against
// the spec test vectors.
func TestBuildBlindedRoute(t *testing.T) {
	t.Parallel()

	// First, we'll read out the raw Json file at the target location.
	jsonBytes, err := os.ReadFile(routeBlindingTestFileName)
	require.NoError(t, err)

	// Once we have the raw file, we'll unpack it into our
	// blindingJsonTestCase struct defined below.
	testCase := &blindingJsonTestCase{}
	require.NoError(t, json.Unmarshal(jsonBytes, testCase))
	require.Len(t, testCase.Generate.Hops, 4)

	// buildPaymentPath is a helper closure used to convert hopData objects
	// into BlindedPathHop objects.
	buildPaymentPath := func(h []hopData) []*HopInfo {
		path := make([]*HopInfo, len(h))
		for i, hop := range h {
			nodeIDStr, _ := hex.DecodeString(hop.NodeID)
			nodeID, _ := btcec.ParsePubKey(nodeIDStr)
			payload, _ := hex.DecodeString(hop.EncodedTLVs)

			path[i] = &HopInfo{
				NodePub:   nodeID,
				PlainText: payload,
			}
		}
		return path
	}

	// First, Eve will build a blinded path from Dave to herself.
	eveSessKey := privKeyFromString(testCase.Generate.Hops[2].SessionKey)
	eveDavePath := buildPaymentPath(testCase.Generate.Hops[2:])
	pathED, err := BuildBlindedPath(eveSessKey, eveDavePath)
	require.NoError(t, err)

	// At this point, Eve will give her blinded path to Bob who will then
	// build his own blinded route from himself to Carol. He will then
	// concatenate the two paths. Note that in his TLV for Carol, Bob will
	// add the `next_blinding_override` field which he will set to the
	// first blinding point in Eve's blinded route. This will indicate to
	// Carol that she should use this point for the next blinding key
	// instead of the next blinding key that she derives.
	bobCarolPath := buildPaymentPath(testCase.Generate.Hops[:2])
	bobSessKey := privKeyFromString(testCase.Generate.Hops[0].SessionKey)
	pathBC, err := BuildBlindedPath(bobSessKey, bobCarolPath)
	require.NoError(t, err)

	// Construct the concatenated path.
	path := &BlindedPath{
		IntroductionPoint: pathBC.Path.IntroductionPoint,
		BlindingPoint:     pathBC.Path.BlindingPoint,
		BlindedHops: append(pathBC.Path.BlindedHops,
			pathED.Path.BlindedHops...),
	}

	// Check that the constructed path is equal to the test vector path.
	require.True(t, equalPubKeys(
		testCase.Route.IntroductionNodeID, path.IntroductionPoint,
	))
	require.True(t, equalPubKeys(
		testCase.Route.Blinding, path.BlindingPoint,
	))

	for i, hop := range testCase.Route.Hops {
		require.True(t, equalPubKeys(
			hop.BlindedNodeID, path.BlindedHops[i].BlindedNodePub,
		))

		data, _ := hex.DecodeString(hop.EncryptedData)
		require.True(
			t, bytes.Equal(data, path.BlindedHops[i].CipherText),
		)
	}

	// Assert that each hop is able to decode the encrypted data meant for
	// it.
	for i, hop := range testCase.Unblind.Hops {
		priv := privKeyFromString(hop.NodePrivKey)
		ephem := pubKeyFromString(hop.EphemeralPubKey)

		data, err := decryptBlindedHopData(
			&PrivKeyECDH{PrivKey: priv}, ephem,
			path.BlindedHops[i].CipherText,
		)
		require.NoError(t, err)

		decoded, _ := hex.DecodeString(hop.DecryptedData)
		require.True(t, bytes.Equal(data, decoded))

		nextEphem, err := NextEphemeral(&PrivKeyECDH{priv}, ephem)
		require.NoError(t, err)

		require.True(t, equalPubKeys(
			hop.NextEphemeralPubKey, nextEphem,
		))
	}
}

// LndDecodeOnion tests that an onion packet can correctly be processed
// by a node in a blinded route.
func TestLndDecodeOnion(t *testing.T) {
	t.Parallel()

	hexString := "67c6697351ff4aec29cdbaabf2fbe3467cc254f81be8e78d765a2e63339fc99a0003c0e3b01c00c76fac237c4c04bf52c0d79b1d790ef2dd862b33e737be3c8f5f04a7a71f0b6abc286046b9f1b8a44c0ad7b46d9fabca0fad7405726d4619f5094706485a4545d09f31b2033afd93cbc3632c9b10718fce192d739d4f54f13162049662e4f9e1b0589399c0b6137e478892b2e2a704658dd019cb1fff42102dfd459291d359ea3fd2f51b63124365f019c034a73cb8fc8040dec289b59d320c8f73c65eb4968f3c789cd56409f1313b9dc2e406c3e4e53b4e1263a94443b4963a0ddc38a3b4489c0b0e021cb3d4cb508e7a8e7590dd86e7375f0291e218c3447435b0be0d141c416eaeac6d0884484fad539d7c55f9738cbb63d35c0116ae2add7b20f83a9c7675833ef00528eefddd13c97716cf0ed7e1216d6320d6ad1420c66d2264d05aa625fa3f47f3fa62bde580798dd82211fed74e3db42c413b6d7cf6a17ba8c6969ac2b6dbd271481b0cfd788feae2963f2f95a84f7af19dab6fa36d507b018ebc9aebae5f1e4b18a8e8607612a8d6455ee42fc1ed2a29b12e58cf3ae4ab9c8b76daddf7ebed3daab93b3746246ea17df5b785e6937a25a35baa6a20c91b25f7484e5441d2b7f24b1f3343d096c3cd6b1f1379960f565feeb02104ff8868e5b5e2186407eac904c295e537374a083370b1ad8b47eb4341a40ffb92208dd44fb3149f3056f1af4dd2424b1e1d2e1570ae3050f92afa1acbb629e8c85a5a0c7a5593837a0b92ed9a396172817b59ddb0cf6843dc4527200eb6278b5ed00f3c0a242d86cddc9cc457aac7b23e406ee80e34d1c58d38fae944c4b276faaa26a7ba23ceaec2586d5e69881e382727dff824297da1fca0c4ce5f9d97d2aabf81c5899bacd1045019cb795a42ee69ce97a8a375ea6d82b54e8fa5351568a240a9fc11be8aff36cb3cc69147a4051dd7d2dfdd3c92da30e37e8dbb5f2a30c05da67f49dac1eb7bdbac9a6221e588a8beb889af9430029f75fe09bd3c83402af3b23f9a990467eb1faef4145ec8b517bbc6739bb10f8ab224c12fc44e5efc95e51a47c983db02c1dfc2d0b35ca9a77de3efdd5d1ffdc56513b00d2ca28c030ef670ddf4f1750ce6a13f3f604af7a6147c0996845a5544b9e871aa0d0f378e4a8c4a220e59a4a69cd6b32663794a54c8f22d75c34d5b72c21f83078d2996c4b3dc86c773475546ef9ad638c2186da55032b70fc23646583116c262a62ea7774f2d0a77da732b02057be3f85cf5537550f846a59e0124a7f4fdb0ceee4ff201182ce67a4201390bed4ca61e208902e5a9b9e6a57863aacea1c0c060c81a161b06b75d090792c25908025f9d2b7e88c3a0693bb5b5ef8407f9448113b3f7ab3fb0bd4800c03e74774a05bd6658a03c31a8ce98d5590a4e0c1f6788eb94f2f8aac0d6af911e871590440ee50ddbd0eb3004ca287f3bc14c746e2addc81062d560f997651844c1615934769f861e272dc8d3a8da1db0721ef1aedeb4e7327041a6d223e1b81417c4b16fdbfae8282f4bd29b94c25fbf8a97ceea60da58c63d2f941b2492025f250691b0908b7f151138cf1113240285e53a24052e77f84b03aa1142bff5aacce721d92d4fff301fcc8aa14de89c9e19de9715e41781c21ab38f1620faaa88320d282c5e2c58306a2cc0d51e2077cf01c9b5dacc46915d708a4e591657004d3bf20add97b830c770124d4406ddd9bb66426baa4e31550438c0522e1c2ba0de1e1fa0135d35b65dbfc6623e660c330423568859c70d1742788a3d0e92f81c5dd6f2027bf4a2fc27620ca6bea9107e35db3ddf33107e84956d511900bef1c4311f0e2385cb4379ffc85fdb31e68e07b1d0000efe302cf89c06ddc7a98efc363efcb101db8ff5a6509cac59858b342fc7fe3f51167dbb731ff46333e159bba94e52597903515d9710695c4f210c006ea3a9ab7b"
	buffer, err := hex.DecodeString(hexString)
	require.NoError(t, err)
	r := bytes.NewReader(buffer[32:])

	priv, _ := btcec.PrivKeyFromBytes(buffer[:32])

	var onion OnionPacket
	err = onion.Decode(r)
	if err != nil {
		println(err.Error())
	}

	log := NewMemoryReplayLog()
	keychain := &PrivKeyECDH{PrivKey: priv}
	associateData := []byte{}
	incomingCltv := uint32(0)
	log.Start()

	router := NewRouter(keychain, log)
	println("Private key:", hex.EncodeToString(priv.Serialize()))
	processedPacket, err := router.ProcessOnionPacket(&onion, associateData, incomingCltv)
	if err != nil {
		t.Fatal(err)
		println(err.Error())
	}

	var sb strings.Builder

	var buf bytes.Buffer
	err = processedPacket.Payload.Encode(&buf)
	if err != nil {
		println(err.Error())
	}

	sb.WriteString("DATA=")
	sb.WriteString(fmt.Sprintf("%x", buf.Bytes()))

	println(sb.String())
}

// TestOnionRouteBlinding tests that an onion packet can correctly be processed
// by a node in a blinded route.
func TestOnionRouteBlinding(t *testing.T) {
	t.Parallel()

	// First, we'll read out the raw Json file at the target location.
	jsonBytes, err := os.ReadFile(onionRouteBlindingTestFileName)
	require.NoError(t, err)

	// Once we have the raw file, we'll unpack it into our
	// blindingJsonTestCase struct defined above.
	testCase := &onionBlindingJsonTestCase{}
	require.NoError(t, json.Unmarshal(jsonBytes, testCase))

	assoc, err := hex.DecodeString(testCase.Generate.AssocData)
	require.NoError(t, err)

	// Extract the original onion packet to be processed.
	onion, err := hex.DecodeString(testCase.Generate.Onion)
	require.NoError(t, err)

	onionBytes := bytes.NewReader(onion)
	onionPacket := &OnionPacket{}
	require.NoError(t, onionPacket.Decode(onionBytes))

	// peelOnion is a helper closure that can be used to set up a Router
	// and use it to process the given onion packet.
	peelOnion := func(key *btcec.PrivateKey,
		blindingPoint *btcec.PublicKey) *ProcessedPacket {

		r := NewRouter(
			&PrivKeyECDH{PrivKey: key}, NewMemoryReplayLog(),
		)

		require.NoError(t, r.Start())
		defer r.Stop()

		res, err := r.ProcessOnionPacket(
			onionPacket, assoc, 10,
			WithBlindingPoint(blindingPoint),
		)
		require.NoError(t, err)

		return res
	}

	hops := testCase.Decrypt.Hops
	require.Len(t, hops, 5)

	// There are some things that the processor of the onion packet will
	// only be able to determine from the actual contents of the encrypted
	// data it receives. These things include the next_blinding_point for
	// the introduction point and the next_blinding_override. The decryption
	// of this data is dependent on the encoding chosen by higher layers.
	// The test uses TLVs. Since the extraction of this data is dependent
	// on layers outside the scope of this library, we provide handle these
	// cases manually for the sake of the test.
	var (
		introPointIndex = 2
		firstBlinding   = pubKeyFromString(hops[1].NextBlinding)

		concatIndex      = 3
		blindingOverride = pubKeyFromString(hops[2].NextBlinding)
	)

	var blindingPoint *btcec.PublicKey
	for i, hop := range testCase.Decrypt.Hops {
		buff := bytes.NewBuffer(nil)
		require.NoError(t, onionPacket.Encode(buff))
		require.Equal(t, hop.Onion, hex.EncodeToString(buff.Bytes()))

		priv := privKeyFromString(hop.NodePrivKey)

		if i == introPointIndex {
			blindingPoint = firstBlinding
		} else if i == concatIndex {
			blindingPoint = blindingOverride
		}

		processedPkt := peelOnion(priv, blindingPoint)

		if blindingPoint != nil {
			blindingPoint, err = NextEphemeral(
				&PrivKeyECDH{priv}, blindingPoint,
			)
			require.NoError(t, err)
		}
		onionPacket = processedPkt.NextPacket
	}
}

type onionBlindingJsonTestCase struct {
	Generate generateOnionData `json:"generate"`
	Decrypt  decryptData       `json:"decrypt"`
}

type generateOnionData struct {
	SessionKey string `json:"session_key"`
	AssocData  string `json:"associated_data"`
	Onion      string `json:"onion"`
}

type decryptData struct {
	Hops []decryptHops `json:"hops"`
}

type decryptHops struct {
	Onion        string `json:"onion"`
	NodePrivKey  string `json:"node_privkey"`
	NextBlinding string `json:"next_blinding"`
}

type blindingJsonTestCase struct {
	Generate generateData `json:"generate"`
	Route    routeData    `json:"route"`
	Unblind  unblindData  `json:"unblind"`
}

type routeData struct {
	IntroductionNodeID string       `json:"introduction_node_id"`
	Blinding           string       `json:"blinding"`
	Hops               []blindedHop `json:"hops"`
}

type unblindData struct {
	Hops []unblindedHop `json:"hops"`
}

type generateData struct {
	Hops []hopData `json:"hops"`
}

type unblindedHop struct {
	NodePrivKey         string `json:"node_privkey"`
	EphemeralPubKey     string `json:"ephemeral_pubkey"`
	DecryptedData       string `json:"decrypted_data"`
	NextEphemeralPubKey string `json:"next_ephemeral_pubkey"`
}

type hopData struct {
	SessionKey  string `json:"session_key"`
	NodeID      string `json:"node_id"`
	EncodedTLVs string `json:"encoded_tlvs"`
}

type blindedHop struct {
	BlindedNodeID string `json:"blinded_node_id"`
	EncryptedData string `json:"encrypted_data"`
}

func equalPubKeys(pkStr string, pk *btcec.PublicKey) bool {
	return hex.EncodeToString(pk.SerializeCompressed()) == pkStr
}

func privKeyFromString(pkStr string) *btcec.PrivateKey {
	bytes, _ := hex.DecodeString(pkStr)
	key, _ := btcec.PrivKeyFromBytes(bytes)
	return key
}

func pubKeyFromString(pkStr string) *btcec.PublicKey {
	bytes, _ := hex.DecodeString(pkStr)
	key, _ := btcec.ParsePubKey(bytes)
	return key
}
