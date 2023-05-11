require "./spec_helper"

TEST_VECTORS_SHA512 = [
  ["", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"],
  ["J", "3c266c0035de59eab2a0dd31b3dcb4a9dd157b310289e5db9ab4f8c2fddb7433466d48f25da7ad735a1cb8f2935aa612ad1f62f0efcece3933ba9979082e2304"],
  ["UQ", "e3a6badd1017cf2af18aa0c8815a7778ce8fdf5e3de314daa598715be8337e444daa5e1ba57c7be747588651e6a8a0e42444208c25dc6a921a73dde3620b4e30"],
  ["3zu", "9178c9ee83f4b7e9756b32b7242a495ccb7630babb20e07b69147b6cada71bc308611840872c0e301750d49a683236562efd6ccd41650f3f0250a0b2f5d01b83"],
  ["SQ34", "8a565d40812cd62efc524beecef17954edb5fd9b13eaee9d72d6f6720f563a78f288436b12f9ab09248ad0692644ada72ccbf911295b801d1e9d70f68edc90d8"],
  ["ksUOe", "6cfbfa4c42d45ca3ccb59473fb0df931b2cf59225b2f7932ef5ebf2a7fcbd76af319746a3d2c67e6d0d05de0f118177927b3b16ba9465af05cccf21ee34d0399"],
  ["cVcjJ4", "337cb5dbb802ae7707cd063336556e9a2ce877e353e09be19f56b78e09a2902fb100bb90531346d75dcfda8e720690aa6b249490126cd939c44ffa55afb67134"],
  ["8F5FQOy", "57e42af08e4f112c0b214bd330d7da45878346ac393950a993308023fccc553faf4e490eeaa4e306c4278d53b6d22ca9be9fcc7a2149c525de1ad2de2413fb60"],
  ["4f3uqBTp", "304f9dea3024e69dfc439d936d2a0c45434fad9c30536033134534a2a37ffdc888aa6c237b344d58fa1e17193ef46f16fce19df40231851164658cb287e394cc"],
  ["nTLqNR3tW", "ab98864a4f51e7851acb001d292e32673841a1fa6c7bf044ee6ecdc34f8a4ce589f265796692b39fa45c27a1d4a62cb73722d1cd4912b020fe174960e0245736"],
  ["vdAYhVtVCk", "7b561dd1e5627a813eae1d381f949d1a10eeac80567c4c3d3f855570099805062caa1c6f5628180cfe19b6f377e39966c9eb5eb0a499475f39d220d7bbfb0e65"],
  ["6xLa68T63Lg", "5de2b20154b5e07e1047186179240e22f16bf6a7c5ecdffbb90bb2bc00d6e6448bb33ca6e072b9c4da45e187b883e76c14b9bd86d642626730dd3738230ff301"],
  ["AtJ52sRObhuH", "eaa1830bab1c6f365666865a794f3782d0f9d6b39930b6744e9f73097d367bee914fa84c699fabee76c9f0e9edcb94bf2c563acf88cf1f1eaea8fbf50d3d3f44"],
]

TEST_VECTORS_BLAKE2B = [
  ["", "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"],
  ["J", "c682580c28dc6449b7866a732f3c65af7666061145136fdeb22c6f5ac700221eabf29dcbd7b065607a198fdd9b6d4768008141d8fbe69412109363296c75631b"],
  ["UQ", "42a65de51f4a7d1843304bf8af6a10d5a7fdf7f6f9aff23502b9fb8f93a34ab838ef4febc3054694ccb0a68527104871018c77f83d80adcc1692028f8379678a"],
  ["3zu", "aec1e3dba2dfaa29b8eccf880b181bd8c8d28a865b9c35f721d96c4535ab0f64c1f1652057dea5edc122a15ac5bf63706e2aeb0cb8b95dd8a76e4ef2adad6080"],
  ["SQ34", "699eacb4d8857488a173d6d8e60e10bf32db986f3a45160f09f58ee59d88d9df902114010cfd00274a215557ea53dc6f5d2590de6020dcd5d9e0c48013230e75"],
  ["ksUOe", "88756316524b3904cfe99a0948484d8b0a48ddb318793fec17bd4e1f53bc64617ed191775bc8fc691dc6fefc4675c0afe544430b7799075958fca68e6ce10634"],
  ["cVcjJ4", "f1acd041248287f753c3904daf3f663cc3161661017a2ad2c82b6a84a1e6e6a846ca532ba21a9841856e6124a9a023aff9a98485ed73138a16dd51f3dab2b2ad"],
  ["8F5FQOy", "52dd10bb2bba1b1cde838d1fe1bb0cb5584e86035f84b92c75bca2dca65c29c40150e9de33850b0529acc4b241c157ffafc97bf158569e299d792ff323e03c48"],
  ["4f3uqBTp", "d27c58872be04e9fabe41fc5c880c4596834fa3b1d69111dec84c0c08ffefc35fc16ee822ebaed51cd75b46aab7a19e6b7e7150cb2d6d5565149410b58383e92"],
  ["nTLqNR3tW", "ea9957431cacac56f7f711c154daeb25401b8ed69ef36857ca65b2c6b8c01b14048000b2e1a8bb84cfcac8c1b593db37b6ba643cfa63f1a8f9eb6f51f32ac20a"],
  ["vdAYhVtVCk", "6ee8d5d21777fdcb40c2dea539606d1754e57fa123ffaa9623e4b8396ea7e4ab0158d77ce5617336e7fd0bc0dcd1d86b3e9409d3f57e6fb016a2e50e0fbe1b12"],
  ["6xLa68T63Lg", "dd53c7d6ca02daa4d40bbd70fa5c25f34c81f469a9de5ddc67c76a4265711c6e4bdaa36c12838f13fc7de68c2bf1d8efeca5539b6901baa9b6ef5e3650e8c053"],
  ["AtJ52sRObhuH", "c26b81d0d6ee6c0decaf657dbc484aac56603b73b41cae1ee0643fec89b72dd20a4f14ca383fda79a2c6f48dcb37f466e71d7d5efd5cf54af0f233f216429e8d"],
]

describe "Crypto.sha512" do
  it "pass test vectors from node.js" do
    TEST_VECTORS_SHA512.each do |(data, hash)|
      Crypto.sha512(data.to_slice).hexstring.should eq hash
    end
  end
end

describe "Crypto.blake2b" do
  it "pass test vectors from well, itself" do
    TEST_VECTORS_BLAKE2B.each do |(data, hash)|
      Crypto.blake2b(data.to_slice).hexstring.should eq hash
    end
  end
end

describe Crypto::Digest::SHA512 do
  it "support Crystal interface of hashes" do
    digest = Crypto::Digest::SHA512.new
    digest << "123"
    digest.final.should eq Crypto.sha512("123".to_slice)
  end
end

describe Crypto::Digest::BLAKE2b do
  it "support Crystal interface of hashes" do
    digest = Crypto::Digest::BLAKE2b.new
    digest << "123"
    digest.final.should eq Crypto.blake2b("123".to_slice)
  end

  it "can be initialized with custom parameters" do
    digest = Crypto::Digest::BLAKE2b.new(hash_size: 32, key: Bytes.new(16))
    digest << "123"
    digest.final.size.should eq 32
  end

  it "verifies size of digest parameters" do
    expect_raises(ArgumentError) { Crypto::Digest::BLAKE2b.new(hash_size: 128) }
    expect_raises(ArgumentError) { Crypto::Digest::BLAKE2b.new(key: Bytes.new(128)) }
  end
end
