import { createSRPClient, createSRPServer } from "../src";
import { getParams } from "../src/params";

// https://datatracker.ietf.org/doc/html/rfc5054#appendix-B
test("RFC 5054 test vector", async () => {
  const testVector = {
    H: "SHA-1" as const,
    size: 1024 as const,
    I: "alice",
    P: "password123",
    N: "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3",
    g: "02",
    k: "7556aa045aef2cdd07abaf0f665c3e818913186f",
    s: "beb25379d1a8581eb5a727673a2441ee",
    x: "94b7555aabe9127cc58ccf4993db6cf84d16c124",
    v: "7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d8129bada1f1822223ca1a605b530e379ba4729fdc59f105b4787e5186f5c671085a1447b52a48cf1970b4fb6f8400bbf4cebfbb168152e08ab5ea53d15c1aff87b2b9da6e04e058ad51cc72bfc9033b564e26480d78e955a5e29e7ab245db2be315e2099afb",
    a: "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
    A: "61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b",
    b: "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
    B: "bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58",
    u: "ce38b9593487da98554ed47d70a7ae5f462ef019",
    S: "b0dc82babcf30674ae450c0287745e7990a3381f63b387aaf271a10d233861e359b48220f7c4693c9ae12b0a6f67809f0876e2d013800d6c41bb59b6d5979b5c00a172b4a2a5903a0bdcaf8a709585eb2afafa8f3499b200210dcc1f10eb33943cd67fc88a2f39a4be5bec4ec0a3212dc346d7e474b29ede8a469ffeca686e5a",
    K: "017eefa1cefc5c2e626e21598987f31e0f1b11bb",
    M1: "3f3bc67169ea71302599cf1b0f5d408b7b65d347",
    M2: "9cab3c575a11de37d3ac1421a9f009236a48eb55",
  };

  const client = createSRPClient(testVector["H"], testVector["size"]);
  const server = createSRPServer(testVector["H"], testVector["size"]);
  const { N, g, k } = getParams(testVector["H"], testVector["size"]);

  expect(N.toHex()).toStrictEqual(testVector["N"]);
  expect(g.toHex()).toStrictEqual(testVector["g"]);
  expect((await k).toHex()).toStrictEqual(testVector["k"]);

  const x = await client.derivePrivateKey(
    testVector["s"],
    testVector["I"],
    testVector["P"],
  );

  expect(x).toStrictEqual(testVector["x"]);

  const v = client.deriveVerifier(x);
  expect(v).toStrictEqual(testVector["v"]);

  const clientSession = await client.deriveSession(
    testVector["a"],
    testVector["B"],
    testVector["s"],
    testVector["I"],
    testVector["x"],
  );

  expect(clientSession.key).toStrictEqual(testVector["K"]);
  expect(clientSession.proof).toStrictEqual(testVector["M1"]);

  const serverSession = await server.deriveSession(
    testVector["b"],
    testVector["A"],
    testVector["s"],
    testVector["I"],
    testVector["v"],
    testVector["M1"],
  );

  expect(serverSession.key).toStrictEqual(testVector["K"]);
  expect(serverSession.proof).toStrictEqual(testVector["M2"]);
});

test("org.bouncycastle.tls.crypto.impl.jcajce.srp test vector", async () => {
  const testVector = {
    H: "SHA-256" as const,
    size: 2048 as const,
    I: "alice",
    P: "password123",
    N: "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73",
    g: "02",
    k: "05b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300",
    s: "beb25379d1a8581eb5a727673a2441ee",
    x: "0065ac38dff8bc34ae0f259e91fbd0f4ca2fa43081c9050cec7cac20d015f303",
    v: "400272a61e185e23784e28a16a149dc60a3790fd45856f79a7070c44f7da1ca22f711cd5bc3592171a875c7812472916de2dcfafc22f7dead8f578f1970547936f9eec686bb3df66ff57f724f6b907e83530812b4ffdbf614153e9fbfed4fc6d972da70bb23f6ccd36ad08b72567fe6bcd2bacb713f2cdb9dc8f81f897f489bb393067d66237a3e061902e72096d5ac1cd1d06c1cd648f7e56da5ec6e0094c1b448c5d63ad2addec1e3d9a3aa7118a0410e53434ddbffc60eef5b82548bda5a2f513209484d3221982ca74668a4d37330cc9cfe3b10f0db368293e43026e3a01440ac732bc1cfb983b512d10296f6951ec5e567329af8e58d7c21ea6c778b0bd",
    a: "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
    A: "4b700f8d48e69c9aae40c684ac7c7c03121e2b7602eb4c3514804ccada0ed4019193a351ecc65a6f854ede91eb096e721b22d701c7adc64e9cedacd75f2e26bb2f5e45dd53dc8dbeafffe82aa49fca0573444691212537a73cf80e25039258205a7edf4749b30adaf25877c62fcd09d6613598bcd4baf2a9727a53706a278148992b2abb23ad5d512d269e16ca11bc0895b5a3b5ec4721cde40a8c39c796e94f0be86dbbeb33da7037018983921aba3f5053195d5ac1da4e567e3c0e75d9e0609f92e850657b2be4771f415b9cacc5c1ecedc30133bf6474f5022c6519d780760ca4d8d3b966b034bd73877c1b3b33f474b9c3c5299a1968f3e6cd3bfe84445a",
    b: "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
    B: "410813e3063f3b4532f2d36413749f39c26c5ceeb1346d3995003c74544c30cba318f981281607ae68dbdc3bee9f0544ada6b13d8ac33217b670973152cf03ef03797615e81dd305342c2e3bb035321d1fd717952e702b09682102d0a5aa25dcee01784a32b0684f75626ca3bf8aec874f2dc11f8926944b06f9948e8ad7649025a58cd9dccdb6b210de00e2283e72baaf93a39b0417dfd1888f841f43d7d41c75b58f654ccb2e8b9c875c42edc34fd3796200312f2abd19b7e2c54b5702cd1a7f4d79fdf73bc418c96466ba122d45474ab6db553417715617f6c3b4a8764279f086acc655e396f85812c90f6f932ce0586168c5deccc9f8beb6891ad13f7caf",
    u: "d56e895d00cb8a9ea81f0c9967522018bca195a485cd59687ebb2a3f5ecda88b",
    S: "30abe90d7091d4617ea8b93f0e649f7fd1ca069bca471e9daf46f5fa5c2b31f05e650da378c0280f144e893ed8137111ff91842c01ce5e3ed8714b4cb23e2b2658230c53153948663239a31b9fdb503325f3bee65f97d081ab90c9453d79c61758e622f4fa4a76b91dfbcf9ab4dac654968756f20b620b500837e297bd51b2d4fde98267703edf69674c3f0e747f910ffec303bc15e004ecaadf3782cd9d2994ed606b7530ad0dd3e9d6de7436fabea3215a13b77a7c59d7fd20ac1df350ad8b8cdcad5ded683073dc2dadeda1350e7d72619bbe652ee53813cb7f3295ada69f53ed595de4de4ea23ffa964157a42785ff6217268f5a912551ba4adb57e8773c",
    K: "899f35b485d44d577957e87cfdd48343d97ea2e0c3e8620594e0b8da9ce5da98",
    M1: "7b1867ca8cc93ab5a9e40a5fd504b28f757a41b5cc5ac7de7ac1078130601c42",
    M2: "91385641bf84309d0321b32ae665d508de8dba72342030d0a5bf46a2f05a53ca",
  };

  const client = createSRPClient(testVector["H"], testVector["size"]);
  const server = createSRPServer(testVector["H"], testVector["size"]);
  const { N, g, k } = getParams(testVector["H"], testVector["size"]);

  expect(N.toHex()).toStrictEqual(testVector["N"]);
  expect(g.toHex()).toStrictEqual(testVector["g"]);
  expect((await k).toHex()).toStrictEqual(testVector["k"]);

  const x = await client.derivePrivateKey(
    testVector["s"],
    testVector["I"],
    testVector["P"],
  );

  expect(x).toStrictEqual(testVector["x"]);

  const v = client.deriveVerifier(x);
  expect(v).toStrictEqual(testVector["v"]);

  const clientSession = await client.deriveSession(
    testVector["a"],
    testVector["B"],
    testVector["s"],
    testVector["I"],
    testVector["x"],
  );

  expect(clientSession.key).toStrictEqual(testVector["K"]);
  expect(clientSession.proof).toStrictEqual(testVector["M1"]);

  const serverSession = await server.deriveSession(
    testVector["b"],
    testVector["A"],
    testVector["s"],
    testVector["I"],
    testVector["v"],
    testVector["M1"],
  );

  expect(serverSession.key).toStrictEqual(testVector["K"]);
  expect(serverSession.proof).toStrictEqual(testVector["M2"]);
});

test("PBKDF2 test vector", async () => {
  const testVector = {
    H: "SHA-256" as const,
    size: 4096 as const,
    I: "",
    P: "password123",
    N: "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff",
    g: "05",
    k: "3509477ea9fca66eadb7cf7b1bd0eb508f54d3989a9c988006a7d0b338374dd2",
    s: "0fe692dde8c45decf7125db90a23b6a06307412d4351858c24a56cbaaf22ba4e",
    x: "5c53fa86448cbe4ca2750b2b519fc9d298d6b2fcb5985d5061ed33384d643733",
    v: "3a32e49e39c13b0a9c444f3a8fcc9546f783da46f034c2da4dd2b5a29d711dd1a4b6d5871a150ecb0514688056fcb70c39e57fbab39d6ca1ad0b4a494664073b83b866d8e811d111d9da73cc1da9ff5dae59760c3790cb5d05483992f3087cc92efe39511be3024648bda48bfa0b6c3d8834ce2162362878b570e08095d15351b11e2c90f59b2956b21954080f9a6cba6c3f74e044901bcdafc98f4f5f0af20f6bb37ecc671f19b7f61799ecf01ea1e12af3a7676b928f37cacc4e9a3751507bb6dc125de0596cf6f109508bf95da95b8b54923544e8543a46b19064b1fc82c3c54f66d3ab3cf8dfd89d40096707157101aed7e5f7ead455687b52ab7459ff40e363e3262f8161dabe647faf22a3ac1a261447a2f429e9200650c9a4e11f5ea2eb56d9dc733b3f91104317c87db420d7aaefbb2042c07a49c7a1b52633244b6bee8a82cb6abbe02ce35a91dbd9eb25499de666937a08393f66161cdb30b55618133ac7af1f376517d774d9c0096430f703efe03658181297481b36050b7d0e5f0109f07542dfbc5ea423d8d7f1da84f854f3b097749ecf16fdde6923d012fe7cbd6474e9c2380cd69de562c9c72e62d486798f7e856b1333be25d2f7223540cb7bb5bb2b2fbeb974acdedd5e0dcdf351c836346ef6f5f847d3cead0d2fe6757161de90ed29567ae8d78b330f55ca250e66aa03a2a73bc5ea8fa0e5193c7cf107",
    a: "cd7d2ffbc2acdcfab8f9d25c3a3b714c65f3c64f3510147787bc318073d89e6b",
    A: "023ed00f1e3365471ec85caa78c9cf1825d8782bee80a7887b96be0fc2f02af28415931c092711863175d424bfa4095a710a05d370384786a9b85007fb14acfc9e4ce84cfcf9dba498cbed1fe9eff2b49b165518b07b763e7864330763b859551948e2c2a2929580bd74c9e2b6d5fa54ab8e473ad9cddab8569b73e0d5e80649b4d5a2d182e1234ba9a880367f99d40165360e850a88f862529cd69e1a49c36f7ef35ce5bd83dced7a58bc05e02c19d5b1790ef0e24c68d5975da7ef33529c271ab9aef8da84709039a2401d6bda676190c4107b2de3c05245a6712d2d8c09a4efdd038e4dcce4ba356133a0b25b3f9d2af7c3145e4d377dbf8a619049500c54664e8ee4fa064fd5f5a227f2eef5ed0c861aea50d0e0f184246e33aa061338ec8dd668a2430a1b43772d85de56da921bd91c98aca5ca18ea0ab65d1a9dba8148c0a12f8d3d4e968456eddf2f13b506b88156ce24e2b68fb33e8d8421c57323b48673d1be369da935d0e4443497a1783bea8aee2f4c5c790dff767e866ff83f73dc0aed0fbae05deffe8e5b61c9f2a516e67f8c29b5951d9bb3f0b5075bb533d973a886ddfb8bdeabbdf3246aeee8e34004ba9fb2e9fd539cec4443415326d4adecd838acb0f93d90ad2ca7a5811651206187cfdea3fc6ccbc3c56bfae5c077f4152856d7d6325ac2a789085480bfb2457cfba45be15210d100c495ff7150a3e0",
    b: "9f5d944d39226a012c7f2234e8e0210130dad939bf5f9b6bbac8383a0a51d9aa",
    B: "9d5318e0a019e6839c7609c96459f73b115cb35def924413a5d4301be2b33e32f8bff88a98bcdc3601a0d964fd79be8a4e054159c225b234b677f725a442150c21ff0725761f0764c7725a5b26fbb1f4e012cad55b794b8a58d312c210e40ce0b799bfa43e3a1d719f8541393f57d78ac807df7bb7a6e6e15c192927aa6e0cc258acc7ff0b8d7eac927c2b0653e1fc85c29792135165dbfe826061392f6e29d838d792994d79f9554dd6b82eb1bf8ee38cce5b74317cc93a04aff8f2041f6d391ad4267ad63f640fd6343c0e4c89e9bb15471d32216dac291cae7e8e646f0d11da15cad6b732a89cde1c9b4e51e9291a9326e06d620f0d3eb9ee0b804829a0c68c858531b67ef6f3a2b87ed83afeb1470de36270cd057ba1b292eac67f27729eeaff634fc37a77e81976d2430079a8b771e648ee7b129873fa6201b29f5ace0fd087ee9574d3d9db2a40402155b5b596db7f5b66ff109cd49d62f13cb0cc352b1d26d89fd597496820a8864ffd3ee085d03a1d06fe76c28f141f2b52d2679680bcefd218a55b6e50becf790ac8c53de2cd1fcd2f467808d961b15128c86f4e3e8e122186d735318c1df6260d7fc0ce226b2beef764c5e051c59791d0f7c953fe762d45d5b5b0acc00e0eeba1d468d45b9936ac2bac714608718049406de9f705202e9a822655728f062013a674d927fd677117161272bd7a5b9f9eda67bddda9",
    u: "1e4dd0557e0ef1d9dc440af9ef9c266beffa4eeb2d76b6bd7fdf5cc1a0879f55",
    S: "6b61b6c18d9f1652e48a29306ea39845936e9c9f275a6fcf6dda82212852b464d536f3f21fa1b38b56e4c0cb4c21f1febcb4fcb891a3fd5f61dc48ed6dd7cf1244f3ae193e99b88ac821706c797c1c5e7299bde630736871fdbf4efff6f645f02dba8996e24e6a7b7e2e666edbb56924af43fb55272899a685dd4e478817df650d9476711a669f7c3cccdb32a4cc0fa6062470e6581ecf170542b3e6171bf60d3538108267171cbf49e9b8f14f1a22231e13c1968a8c747939475c258bd8dc02f6e35f11c941c2ac85f3372824b2e87f2a8b5509c48f2d7ec62a4e1fa303f36a84a2c159c27f8983869564e10689af6bec6aaba664d7618dd445f6a01639c03a1b202b88943bf9097fc5e24be7a5148fafc45292171aea4ac3a440219de23fcf8f1d764534e9681afc724734012068371e36d7638b12ac4ee9198fd13b2e4aaadeb905a1cdab8e47a2cf305f4e6e4ff940540304f95400de159e6effadad297d8012825eea8715510a1e045b31f4cb2b5669d03f58c7552b2f7f5005176a6925ea423e7495e844af7ea6edaae4f9bd714348d049763a8206cdd60e1cc0c31f80633af945bb79671037055755951d28fe609115298a50bf85c26019a1b010c89de000e075566c5f34c158b752011fac6501e0ebd5eb3f8b01418887df1e0ff53f438aa609c5b63add7d5fd1e94b446b4bbe06ea6d738d8c01cd21c4e95eeab9bf",
    K: "2170a39de5a234cb0c33b25a264a4f1ff395341ec4b1cc4997a6f821176fb1d6",
    M1: "a2e77e3fad4270b1d9c0aa9956c672ea5cb6140dd44addbda3628088b039ae59",
    M2: "bfce2363db9d223d098a6d8815df5a104617f10e48e8dd252da2301eafc92701",
  };

  const client = createSRPClient(testVector["H"], testVector["size"]);
  const server = createSRPServer(testVector["H"], testVector["size"]);
  const { N, g, k } = getParams(testVector["H"], testVector["size"]);

  expect(N.toHex()).toStrictEqual(testVector["N"]);
  expect(g.toHex()).toStrictEqual(testVector["g"]);
  expect((await k).toHex()).toStrictEqual(testVector["k"]);

  const x = await client.deriveSafePrivateKey(testVector["s"], testVector["P"]);
  expect(x).toStrictEqual(testVector["x"]);

  const v = client.deriveVerifier(x);
  expect(v).toStrictEqual(testVector["v"]);

  const clientSession = await client.deriveSession(
    testVector["a"],
    testVector["B"],
    testVector["s"],
    testVector["I"],
    testVector["x"],
  );

  expect(clientSession.key).toStrictEqual(testVector["K"]);
  expect(clientSession.proof).toStrictEqual(testVector["M1"]);

  const serverSession = await server.deriveSession(
    testVector["b"],
    testVector["A"],
    testVector["s"],
    testVector["I"],
    testVector["v"],
    testVector["M1"],
  );

  expect(serverSession.key).toStrictEqual(testVector["K"]);
  expect(serverSession.proof).toStrictEqual(testVector["M2"]);
});
