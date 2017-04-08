package chacha20_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/codahale/chacha20"
)

// stolen from https://tools.ietf.org/html/draft-strombergson-chacha-test-vectors-01
type testVector struct {
	key       string
	nonce     string
	rounds    uint8
	keyStream string
}

var testVectors = []testVector{
	testVector{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000",
		8,
		"3e00ef2f895f40d67f5bb8e81f09a5a12c840ec3ce9a7f3b181be188ef711a1e" +
			"984ce172b9216f419f445367456d5619314a42a3da86b001387bfdb80e0cfe42" +
			"d2aefa0deaa5c151bf0adb6c01f2a5adc0fd581259f9a2aadcf20f8fd566a26b" +
			"5032ec38bbc5da98ee0c6f568b872a65a08abf251deb21bb4b56e5d8821e68aa",
	},
	testVector{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000",
		12,
		"9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f" +
			"0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be" +
			"0bd58841203e74fe86fc71338ce0173dc628ebb719bdcbcc151585214cc089b4" +
			"42258dcda14cf111c602b8971b8cc843e91e46ca905151c02744a6b017e69316",
	},
	testVector{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000",
		20,
		"76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7" +
			"da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586" +
			"9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed" +
			"29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
	},
	testVector{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000",
		8,
		"cf5ee9a0494aa9613e05d5ed725b804b12f4a465ee635acc3a311de8740489ea" +
			"289d04f43c7518db56eb4433e498a1238cd8464d3763ddbb9222ee3bd8fae3c8" +
			"b4355a7d93dd8867089ee643558b95754efa2bd1a8a1e2d75bcdb32015542638" +
			"291941feb49965587c4fdfe219cf0ec132a6cd4dc067392e67982fe53278c0b4",
	},
	testVector{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000",
		12,
		"12056e595d56b0f6eef090f0cd25a20949248c2790525d0f930218ff0b4ddd10" +
			"a6002239d9a454e29e107a7d06fefdfef0210feba044f9f29b1772c960dc29c0" +
			"0c7366c5cbc604240e665eb02a69372a7af979b26fbb78092ac7c4b88029a7c8" +
			"54513bc217bbfc7d90432e308eba15afc65aeb48ef100d5601e6afba257117a9",
	},
	testVector{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000",
		20,
		"c5d30a7ce1ec119378c84f487d775a8542f13ece238a9455e8229e888de85bbd" +
			"29eb63d0a17a5b999b52da22be4023eb07620a54f6fa6ad8737b71eb0464dac0" +
			"10f656e6d1fd55053e50c4875c9930a33f6d0263bd14dfd6ab8c70521c19338b" +
			"2308b95cf8d0bb7d202d2102780ea3528f1cb48560f76b20f382b942500fceac",
	},
	testVector{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000",
		8,
		"2b8f4bb3798306ca5130d47c4f8d4ed13aa0edccc1be6942090faeeca0d7599b" +
			"7ff0fe616bb25aa0153ad6fdc88b954903c22426d478b97b22b8f9b1db00cf06" +
			"470bdffbc488a8b7c701ebf4061d75c5969186497c95367809afa80bd843b040" +
			"a79abc6e73a91757f1db73c8eacfa543b38f289d065ab2f3032d377b8c37fe46",
	},
	testVector{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000",
		12,
		"64b8bdf87b828c4b6dbaf7ef698de03df8b33f635714418f9836ade59be12969" +
			"46c953a0f38ecffc9ecb98e81d5d99a5edfc8f9a0a45b9e41ef3b31f028f1d0f" +
			"559db4a7f222c442fe23b9a2596a88285122ee4f1363896ea77ca150912ac723" +
			"bff04b026a2f807e03b29c02077d7b06fc1ab9827c13c8013a6d83bd3b52a26f",
	},
	testVector{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000",
		20,
		"ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32" +
			"111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b" +
			"5305e5e44aff19b235936144675efbe4409eb7e8e5f1430f5f5836aeb49bb532" +
			"8b017c4b9dc11f8a03863fa803dc71d5726b2b6b31aa32708afe5af1d6b69058",
	},
	testVector{
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ffffffffffffffff",
		8,
		"e163bbf8c9a739d18925ee8362dad2cdc973df05225afb2aa26396f2a9849a4a" +
			"445e0547d31c1623c537df4ba85c70a9884a35bcbf3dfab077e98b0f68135f54" +
			"81d4933f8b322ac0cd762c27235ce2b31534e0244a9a2f1fd5e94498d47ff108" +
			"790c009cf9e1a348032a7694cb28024cd96d3498361edb1785af752d187ab54b",
	},
	testVector{
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ffffffffffffffff",
		12,
		"04bf88dae8e47a228fa47b7e6379434ba664a7d28f4dab84e5f8b464add20c3a" +
			"caa69c5ab221a23a57eb5f345c96f4d1322d0a2ff7a9cd43401cd536639a615a" +
			"5c9429b55ca3c1b55354559669a154aca46cd761c41ab8ace385363b95675f06" +
			"8e18db5a673c11291bd4187892a9a3a33514f3712b26c13026103298ed76bc9a",
	},
	testVector{
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ffffffffffffffff",
		20,
		"d9bf3f6bce6ed0b54254557767fb57443dd4778911b606055c39cc25e674b836" +
			"3feabc57fde54f790c52c8ae43240b79d49042b777bfd6cb80e931270b7f50eb" +
			"5bac2acd86a836c5dc98c116c1217ec31d3a63a9451319f097f3b4d6dab07787" +
			"19477d24d24b403a12241d7cca064f790f1d51ccaff6b1667d4bbca1958c4306",
	},
	testVector{
		"5555555555555555555555555555555555555555555555555555555555555555",
		"5555555555555555",
		8,
		"7cb78214e4d3465b6dc62cf7a1538c88996952b4fb72cb6105f1243ce3442e29" +
			"75a59ebcd2b2a598290d7538491fe65bdbfefd060d88798120a70d049dc2677d" +
			"d48ff5a2513e497a5d54802d7484c4f1083944d8d0d14d6482ce09f7e5ebf20b" +
			"29807d62c31874d02f5d3cc85381a745ecbc60525205e300a76961bfe51ac07c",
	},
	testVector{
		"5555555555555555555555555555555555555555555555555555555555555555",
		"5555555555555555",
		12,
		"a600f07727ff93f3da00dd74cc3e8bfb5ca7302f6a0a2944953de00450eecd40" +
			"b860f66049f2eaed63b2ef39cc310d2c488f5d9a241b615dc0ab70f921b91b95" +
			"140eff4aa495ac61289b6bc57de072419d09daa7a7243990daf348a8f2831e59" +
			"7cf379b3b284f00bda27a4c68085374a8a5c38ded62d1141cae0bb838ddc2232",
	},
	testVector{
		"5555555555555555555555555555555555555555555555555555555555555555",
		"5555555555555555",
		20,
		"bea9411aa453c5434a5ae8c92862f564396855a9ea6e22d6d3b50ae1b3663311" +
			"a4a3606c671d605ce16c3aece8e61ea145c59775017bee2fa6f88afc758069f7" +
			"e0b8f676e644216f4d2a3422d7fa36c6c4931aca950e9da42788e6d0b6d1cd83" +
			"8ef652e97b145b14871eae6c6804c7004db5ac2fce4c68c726d004b10fcaba86",
	},
	testVector{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"aaaaaaaaaaaaaaaa",
		8,
		"40f9ab86c8f9a1a0cdc05a75e5531b612d71ef7f0cf9e387df6ed6972f0aae21" +
			"311aa581f816c90e8a99de990b6b95aac92450f4e112712667b804c99e9c6eda" +
			"f8d144f560c8c0ea36880d3b77874c9a9103d147f6ded386284801a4ee158e5e" +
			"a4f9c093fc55fd344c33349dc5b699e21dc83b4296f92ee3ecabf3d51f95fe3f",
	},
	testVector{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"aaaaaaaaaaaaaaaa",
		12,
		"856505b01d3b47aae03d6a97aa0f033a9adcc94377babd8608864fb3f625b6e3" +
			"14f086158f9f725d811eeb953b7f747076e4c3f639fa841fad6c9a709e621397" +
			"6dd6ee9b5e1e2e676b1c9e2b82c2e96c1648437bff2f0126b74e8ce0a9b06d17" +
			"20ac0b6f09086f28bc201587f0535ed9385270d08b4a9382f18f82dbde18210e",
	},
	testVector{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"aaaaaaaaaaaaaaaa",
		20,
		"9aa2a9f656efde5aa7591c5fed4b35aea2895dec7cb4543b9e9f21f5e7bcbcf3" +
			"c43c748a970888f8248393a09d43e0b7e164bc4d0b0fb240a2d72115c4808906" +
			"72184489440545d021d97ef6b693dfe5b2c132d47e6f041c9063651f96b623e6" +
			"2a11999a23b6f7c461b2153026ad5e866a2e597ed07b8401dec63a0934c6b2a9",
	},
	testVector{
		"00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100",
		"0f1e2d3c4b5a6978",
		8,
		"db43ad9d1e842d1272e4530e276b3f568f8859b3f7cf6d9d2c74fa53808cb515" +
			"7a8ebf46ad3dcc4b6c7dadde131784b0120e0e22f6d5f9ffa7407d4a21b695d9" +
			"c5dd30bf55612fab9bdd118920c19816470c7f5dcd42325dbbed8c57a56281c1" +
			"44cb0f03e81b3004624e0650a1ce5afaf9a7cd8163f6dbd72602257dd96e471e",
	},
	testVector{
		"00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100",
		"0f1e2d3c4b5a6978",
		12,
		"7ed12a3a63912ae941ba6d4c0d5e862e568b0e5589346935505f064b8c2698db" +
			"f7d850667d8e67be639f3b4f6a16f92e65ea80f6c7429445da1fc2c1b9365040" +
			"e32e50c4106f3b3da1ce7ccb1e7140b153493c0f3ad9a9bcff077ec4596f1d0f" +
			"29bf9cbaa502820f732af5a93c49eee33d1c4f12af3b4297af91fe41ea9e94a2",
	},
	testVector{
		"00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100",
		"0f1e2d3c4b5a6978",
		20,
		"9fadf409c00811d00431d67efbd88fba59218d5d6708b1d685863fabbb0e961e" +
			"ea480fd6fb532bfd494b2151015057423ab60a63fe4f55f7a212e2167ccab931" +
			"fbfd29cf7bc1d279eddf25dd316bb8843d6edee0bd1ef121d12fa17cbc2c574c" +
			"ccab5e275167b08bd686f8a09df87ec3ffb35361b94ebfa13fec0e4889d18da5",
	},
	testVector{
		"c46ec1b18ce8a878725a37e780dfb7351f68ed2e194c79fbc6aebee1a667975d",
		"1ada31d5cf688221",
		8,
		"838751b42d8ddd8a3d77f48825a2ba752cf4047cb308a5978ef274973be374c9" +
			"6ad848065871417b08f034e681fe46a93f7d5c61d1306614d4aaf257a7cff08b" +
			"16f2fda170cc18a4b58a2667ed962774af792a6e7f3c77992540711a7a136d7e" +
			"8a2f8d3f93816709d45a3fa5f8ce72fde15be7b841acba3a2abd557228d9fe4f",
	},
	testVector{
		"c46ec1b18ce8a878725a37e780dfb7351f68ed2e194c79fbc6aebee1a667975d",
		"1ada31d5cf688221",
		12,
		"1482072784bc6d06b4e73bdc118bc0103c7976786ca918e06986aa251f7e9cc1" +
			"b2749a0a16ee83b4242d2e99b08d7c20092b80bc466c87283b61b1b39d0ffbab" +
			"d94b116bc1ebdb329b9e4f620db695544a8e3d9b68473d0c975a46ad966ed631" +
			"e42aff530ad5eac7d8047adfa1e5113c91f3e3b883f1d189ac1c8fe07ba5a42b",
	},
	testVector{
		"c46ec1b18ce8a878725a37e780dfb7351f68ed2e194c79fbc6aebee1a667975d",
		"1ada31d5cf688221",
		20,
		"f63a89b75c2271f9368816542ba52f06ed49241792302b00b5e8f80ae9a473af" +
			"c25b218f519af0fdd406362e8d69de7f54c604a6e00f353f110f771bdca8ab92" +
			"e5fbc34e60a1d9a9db17345b0a402736853bf910b060bdf1f897b6290f01d138" +
			"ae2c4c90225ba9ea14d518f55929dea098ca7a6ccfe61227053c84e49a4a3332",
	},
}

func TestChaCha20(t *testing.T) {
	for i, vector := range testVectors {
		if vector.rounds == 20 {
			t.Logf("Running test vector %d", i)

			key, err := hex.DecodeString(vector.key)
			if err != nil {
				t.Error(err)
			}

			nonce, err := hex.DecodeString(vector.nonce)
			if err != nil {
				t.Error(err)
			}

			c, err := chacha20.New(key, nonce)
			if err != nil {
				t.Error(err)
			}

			expected, err := hex.DecodeString(vector.keyStream)
			if err != nil {
				t.Error(err)
			}

			src := make([]byte, len(expected))
			dst := make([]byte, len(expected))
			c.XORKeyStream(dst, src)

			if !bytes.Equal(expected, dst) {
				t.Errorf("Bad keystream: expected %x, was %x", expected, dst)

				for i, v := range expected {
					if dst[i] != v {
						t.Logf("Mismatch at offset %d: %x vs %x", i, v, dst[i])
						break
					}
				}
			}
		}
	}
}

func TestChaCha20WithRounds(t *testing.T) {
	for i, vector := range testVectors {
		t.Logf("Running test vector %d", i)

		key, err := hex.DecodeString(vector.key)
		if err != nil {
			t.Error(err)
		}

		nonce, err := hex.DecodeString(vector.nonce)
		if err != nil {
			t.Error(err)
		}

		c, err := chacha20.NewWithRounds(key, nonce, vector.rounds)
		if err != nil {
			t.Error(err)
		}

		expected, err := hex.DecodeString(vector.keyStream)
		if err != nil {
			t.Error(err)
		}

		src := make([]byte, len(expected))
		dst := make([]byte, len(expected))
		c.XORKeyStream(dst, src)

		if !bytes.Equal(expected, dst) {
			t.Errorf("Bad keystream: expected %x, was %x", expected, dst)

			for i, v := range expected {
				if dst[i] != v {
					t.Logf("Mismatch at offset %d: %x vs %x", i, v, dst[i])
					break
				}
			}
		}
	}
}

func TestXChaCha20(t *testing.T) {
	key := []byte{
		0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
		0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
		0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
		0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89,
	}
	nonce := []byte{
		0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
		0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
		0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37,
	}
	expectedKeyStream := []byte{
		0x4f, 0xeb, 0xf2, 0xfe, 0x4b, 0x35, 0x9c, 0x50,
		0x8d, 0xc5, 0xe8, 0xb5, 0x98, 0x0c, 0x88, 0xe3,
		0x89, 0x46, 0xd8, 0xf1, 0x8f, 0x31, 0x34, 0x65,
		0xc8, 0x62, 0xa0, 0x87, 0x82, 0x64, 0x82, 0x48,
		0x01, 0x8d, 0xac, 0xdc, 0xb9, 0x04, 0x17, 0x88,
		0x53, 0xa4, 0x6d, 0xca, 0x3a, 0x0e, 0xaa, 0xee,
		0x74, 0x7c, 0xba, 0x97, 0x43, 0x4e, 0xaf, 0xfa,
		0xd5, 0x8f, 0xea, 0x82, 0x22, 0x04, 0x7e, 0x0d,
		0xe6, 0xc3, 0xa6, 0x77, 0x51, 0x06, 0xe0, 0x33,
		0x1a, 0xd7, 0x14, 0xd2, 0xf2, 0x7a, 0x55, 0x64,
		0x13, 0x40, 0xa1, 0xf1, 0xdd, 0x9f, 0x94, 0x53,
		0x2e, 0x68, 0xcb, 0x24, 0x1c, 0xbd, 0xd1, 0x50,
		0x97, 0x0d, 0x14, 0xe0, 0x5c, 0x5b, 0x17, 0x31,
		0x93, 0xfb, 0x14, 0xf5, 0x1c, 0x41, 0xf3, 0x93,
		0x83, 0x5b, 0xf7, 0xf4, 0x16, 0xa7, 0xe0, 0xbb,
		0xa8, 0x1f, 0xfb, 0x8b, 0x13, 0xaf, 0x0e, 0x21,
		0x69, 0x1d, 0x7e, 0xce, 0xc9, 0x3b, 0x75, 0xe6,
		0xe4, 0x18, 0x3a,
	}

	c, err := chacha20.NewXChaCha(key, nonce)
	if err != nil {
		t.Error(err)
	}
	buf := make([]byte, len(expectedKeyStream))
	c.XORKeyStream(buf, buf)
	if !bytes.Equal(expectedKeyStream, buf) {
		t.Errorf("Bad keystream: expected %x, was %x", expectedKeyStream, buf)
	}
}

func TestBadKeySize(t *testing.T) {
	key := make([]byte, 3)
	nonce := make([]byte, chacha20.NonceSize)

	_, err := chacha20.New(key, nonce)

	if err != chacha20.ErrInvalidKey {
		t.Error("Should have rejected an invalid key")
	}
}

func TestBadNonceSize(t *testing.T) {
	key := make([]byte, chacha20.KeySize)
	nonce := make([]byte, 3)

	_, err := chacha20.New(key, nonce)

	if err != chacha20.ErrInvalidNonce {
		t.Error("Should have rejected an invalid nonce")
	}
}

func TestBadRoundNumber(t *testing.T) {
	key := make([]byte, chacha20.KeySize)
	nonce := make([]byte, chacha20.NonceSize)

	_, err := chacha20.NewWithRounds(key, nonce, 5)

	if err != chacha20.ErrInvalidRounds {
		t.Error("Should have rejected an invalid round number")
	}
}

func ExampleCipher() {
	key, err := hex.DecodeString("60143a3d7c7137c3622d490e7dbb85859138d198d9c648960e186412a6250722")
	if err != nil {
		panic(err)
	}

	// A nonce should only be used once. Generate it randomly.
	nonce, err := hex.DecodeString("308c92676fa95973")
	if err != nil {
		panic(err)
	}

	c, err := chacha20.New(key, nonce)
	if err != nil {
		panic(err)
	}

	src := []byte("hello I am a secret message")
	dst := make([]byte, len(src))

	c.XORKeyStream(dst, src)

	fmt.Printf("%x\n", dst)
	// Output:
	// a05452ebd981422dcdab2c9cde0d20a03f769e87d3e976ee6d6a11
}
