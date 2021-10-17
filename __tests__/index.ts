import { createSRPClient, createSRPServer } from "../src";
import { getParams } from "../src/params";
import { SRPInt } from "../src/SRPInt";

test("should authenticate a user", async () => {
  const client = createSRPClient("SHA-256", 2048);
  const server = createSRPServer("SHA-256", 2048);

  const username = "linus@folkdatorn.se";
  const password = "$uper$ecure";

  const salt = client.generateSalt();
  const privateKey = await client.derivePrivateKey(salt, username, password);
  const verifier = client.deriveVerifier(privateKey);

  const clientEphemeral = client.generateEphemeral();
  const serverEphemeral = await server.generateEphemeral(verifier);

  const clientSession = await client.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    username,
    privateKey,
  );

  const serverSession = await server.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    username,
    verifier,
    clientSession.proof,
  );

  await client.verifySession(
    clientEphemeral.public,
    clientSession,
    serverSession.proof,
  );

  expect(clientSession.key).toStrictEqual(serverSession.key);
});

test("SRPInt should keep padding when going back and forth", () => {
  expect(SRPInt.fromHex("a").toHex()).toStrictEqual("a");
  expect(SRPInt.fromHex("0a").toHex()).toStrictEqual("0a");
  expect(SRPInt.fromHex("00a").toHex()).toStrictEqual("00a");
  expect(SRPInt.fromHex("000a").toHex()).toStrictEqual("000a");
  expect(SRPInt.fromHex("0000a").toHex()).toStrictEqual("0000a");
  expect(SRPInt.fromHex("00000a").toHex()).toStrictEqual("00000a");
  expect(SRPInt.fromHex("000000a").toHex()).toStrictEqual("000000a");
  expect(SRPInt.fromHex("0000000a").toHex()).toStrictEqual("0000000a");
  expect(SRPInt.fromHex("00000000a").toHex()).toStrictEqual("00000000a");
});

test("should match known test vector", async () => {
  const testVector = {
    H: "SHA-256" as const,
    size: 2048 as const,
    N: "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73",
    g: "02",
    I: "alice",
    P: "password123",
    s: "beb25379d1a8581eb5a727673a2441ee",
    k: "05b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300",
    x: "0065ac38dff8bc34ae0f259e91fbd0f4ca2fa43081c9050cec7cac20d015f303",
    v: "400272a61e185e23784e28a16a149dc60a3790fd45856f79a7070c44f7da1ca22f711cd5bc3592171a875c7812472916de2dcfafc22f7dead8f578f1970547936f9eec686bb3df66ff57f724f6b907e83530812b4ffdbf614153e9fbfed4fc6d972da70bb23f6ccd36ad08b72567fe6bcd2bacb713f2cdb9dc8f81f897f489bb393067d66237a3e061902e72096d5ac1cd1d06c1cd648f7e56da5ec6e0094c1b448c5d63ad2addec1e3d9a3aa7118a0410e53434ddbffc60eef5b82548bda5a2f513209484d3221982ca74668a4d37330cc9cfe3b10f0db368293e43026e3a01440ac732bc1cfb983b512d10296f6951ec5e567329af8e58d7c21ea6c778b0bd",
    a: "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
    b: "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
    A: "4b700f8d48e69c9aae40c684ac7c7c03121e2b7602eb4c3514804ccada0ed4019193a351ecc65a6f854ede91eb096e721b22d701c7adc64e9cedacd75f2e26bb2f5e45dd53dc8dbeafffe82aa49fca0573444691212537a73cf80e25039258205a7edf4749b30adaf25877c62fcd09d6613598bcd4baf2a9727a53706a278148992b2abb23ad5d512d269e16ca11bc0895b5a3b5ec4721cde40a8c39c796e94f0be86dbbeb33da7037018983921aba3f5053195d5ac1da4e567e3c0e75d9e0609f92e850657b2be4771f415b9cacc5c1ecedc30133bf6474f5022c6519d780760ca4d8d3b966b034bd73877c1b3b33f474b9c3c5299a1968f3e6cd3bfe84445a",
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

// https://datatracker.ietf.org/doc/html/rfc5054#appendix-B
test("should match rfc5054 test vector", async () => {
  const testVector = {
    H: "SHA-1" as const,
    size: 1024 as const,
    N: "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3",
    g: "02",
    I: "alice",
    P: "password123",
    s: "beb25379d1a8581eb5a727673a2441ee",
    k: "7556aa045aef2cdd07abaf0f665c3e818913186f",
    x: "94b7555aabe9127cc58ccf4993db6cf84d16c124",
    v: "7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d8129bada1f1822223ca1a605b530e379ba4729fdc59f105b4787e5186f5c671085a1447b52a48cf1970b4fb6f8400bbf4cebfbb168152e08ab5ea53d15c1aff87b2b9da6e04e058ad51cc72bfc9033b564e26480d78e955a5e29e7ab245db2be315e2099afb",
    a: "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
    b: "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
    A: "61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b",
    B: "bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58",
    u: "ce38b9593487da98554ed47d70a7ae5f462ef019",
    // S = premaster secret
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
