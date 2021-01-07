let globby = require("globby");
let fs = require("fs-extra");
let path = require("path");

const yargs = require("yargs/yargs");
const { hideBin } = require("yargs/helpers");
const argv = yargs(hideBin(process.argv)).argv;

const VST_DIR = argv.dir || __dirname;
const VST_GLOB = "/**/*.dll";

const VST64Dir = path.resolve(path.join(VST_DIR, "64")).replace(/\\/g, "/");

const VST32Dir = path
  .resolve(path.join(VST_DIR, "32_linked"))
  .replace(/\\/g, "/");

const SCAN_GLOB = path
  .resolve(path.join(VST_DIR, VST_GLOB))
  .replace(/\\/g, "/");

console.log(SCAN_GLOB);

function getArchInformation(result) {
  var index = result.indexOf("PE");
  var archIdentifier = result[index + 4].toString(16).toLowerCase();
  switch (archIdentifier) {
    case "4c":
      return "32-bit";
    case "64":
      return "64-bit";
  }
  return "unknown";
}

let listFiles = async () => {
  let files = await globby(SCAN_GLOB);
  let tableInfo = files.map(async (f, i) => {
    let result = await fs.readFile(f);
    let r = {
      file: f,
      name: path.basename(f),
      architecture: getArchInformation(result),
    };
    return r;
  });

  function listPlugins(label, plugs) {
    if (plugs.length) {
      console.log(`${label} Plugins: ${plugs.length}`);
      console.table(plugs);
    }
  }

  function enforceDir(dir) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const generateSymlink = (outputDir) => (item, index) => {
    //console.log(item.file, outputDir);
    const root = path.resolve(VST_DIR).replace(/\\/g, "/");
    const predicate = item.file.replace(root, "");
    const newFile = path
      .resolve(path.join(outputDir, predicate))
      .replace(/\\/g, "/");
    console.log(newFile);
    try {
      enforceDir(path.dirname(newFile));
      fs.symlinkSync(item.file, newFile, "file");
    } catch (err) {
      console.log(err);
    }
  };

  const processPlugins = (plugins) => {
    const plug32 = plugins.filter((p) => p.architecture == "32-bit");
    const plug64 = plugins.filter((p) => p.architecture == "64-bit");
    const plugUnknown = plugins.filter((p) => p.architecture == "unknown");

    if (argv.list) {
      listPlugins("32 Bit", plug32);
      listPlugins("64 Bit", plug64);
      listPlugins("??????", plugUnknown);
    }

    if (argv.sortArch) {
      //plug32.forEach(generateSymlink(VST32Dir));
      plug64.forEach(generateSymlink(VST64Dir));
    }
  };

  Promise.all(tableInfo).then(processPlugins);
};

listFiles();
