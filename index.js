let globby = require("globby");
let fs = require("fs-extra");
let path = require("path");

const VST_DIR = __dirname;
const VST_GLOB = "VST/**/*.dll";

const SCAN_GLOB = path
  .resolve(path.join(VST_DIR, VST_GLOB))
  .replace(/\\/g, "/");

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
      name: path.basename(f),
      architecture: getArchInformation(result),
    };
    return r;
  });

  Promise.all(tableInfo).then((plugins) => {
    console.table(plugins);
  });
};

listFiles();
