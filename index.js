let globby = require("globby");
let fs = require("fs-extra");
let path = require("path");

const yargs = require("yargs/yargs");
const { hideBin } = require("yargs/helpers");
const argv = yargs(hideBin(process.argv)).argv;
const { printTable, Table } = require("console-table-printer");

const VST_DIR = argv.dir || __dirname;
const VST_GLOB = "/**/*.dll";
const DEDUPE_ARCH = argv.dedupeArch == "false" ? false : true;
const SHOW_SKIPPED = argv.showSkipped == "false" ? false : true;
const SHOW_MATCHED = argv.showMatched == "false" ? false : true;

const VST64Dir = path.resolve(path.join(VST_DIR, "../64")).replace(/\\/g, "/");

const VST32Dir = path.resolve(path.join(VST_DIR, "../32")).replace(/\\/g, "/");

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

  function sortListPlugins(a, b) {
    let _a = a.file.toString();
    let _b = b.file.toString();
    return _a > _b ? 1 : -1;
  }

  const possibleMatch = (p, root) => (checkPlug, i) => {
    let _fileP = p.file.replace(root, "");
    let _dirP = path.dirname(_fileP);
    let creatorP = _dirP.split("/")[1];

    let _fileCP = checkPlug.file.replace(root, "");
    let _dirCP = path.dirname(_fileCP);
    let creatorCP = _dirCP.split("/")[1];

    let pad = 80;

    if (creatorP === creatorCP) {
      let plugP = _dirP.split("/")[2];
      let plugCP = _dirCP.split("/")[2];
      if (plugP == plugCP) {
        //console.log(i, _fileP.padEnd(50, " "), _fileCP);
        return true;
      }
    }

    return false;
  };

  function listPlugins(label, plugs, plugsChecklist) {
    if (plugs.length) {
      const root = path.resolve(VST_DIR).replace(/\\/g, "/");
      const _plugs = plugs.sort(sortListPlugins);
      const _plugsChecklist = plugsChecklist.sort(sortListPlugins);
      let table = _plugs.map((p) => {
        let _file = p.file.replace(root, "");
        let _dir = path.dirname(_file);
        return {
          arch: p.architecture,
          creator: _dir.split("/")[1],
          plug: _dir.split("/").splice(2, 999).join(" | "),
          name: path.basename(_file),
          match: _plugsChecklist.find(possibleMatch(p, root)) ? "Y" : "",
        };
      });

      printTable(label, table);
    }
  }

  function printTable(label, table) {
    console.log(`${label} Plugins: ${table.length}`);
    let p = new Table();

    let lastCreator = null;
    let stripes = ["blue", "magenta", "cyan"];
    let stripeIndex = -1;
    let currentColor = null;
    table.forEach((tr, i) => {
      if (tr.creator !== lastCreator) {
        lastCreator = tr.creator;
        stripeIndex++;
        if (stripeIndex > stripes.length - 1) {
          stripeIndex = 0;
        }
        currentColor = stripes[stripeIndex];
      }
      let color = { color: currentColor };
      if (tr.match) {
        color = { color: "yellow" };
      }
      let _tr = tr;
      p.addRow(_tr, color);
    });
    p.printTable();
  }

  function enforceDir(dir) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const generateSymlink = (outputDir, report, arch, plugsChecklist) => (
    item,
    index
  ) => {
    //console.log(item.file, outputDir);
    const root = path.resolve(VST_DIR).replace(/\\/g, "/");
    const predicate = item.file.replace(root, "");
    const newFile = path
      .resolve(path.join(outputDir, predicate))
      .replace(/\\/g, "/");

    //does this plugin have a match?
    let matchingPlugin = null;
    if (DEDUPE_ARCH && plugsChecklist && plugsChecklist.length) {
      matchingPlugin = plugsChecklist.find(possibleMatch(item, root)) || null;
    }

    try {
      enforceDir(path.dirname(newFile));
      if (matchingPlugin) {
        SHOW_MATCHED && report.push({ status: "☒ matched", newFile, arch });
      } else if (!fs.existsSync(newFile)) {
        fs.symlinkSync(item.file, newFile, "file");
        report.push({ status: "✓ linked", newFile, arch });
      } else if (fs.existsSync(newFile)) {
        SHOW_SKIPPED && report.push({ status: "✗ skipped", newFile, arch });
      } else {
        report.push({ status: "???", newFile, arch });
      }
    } catch (err) {
      console.log(err);
    }
  };

  function printReport(data) {
    const root = path.resolve(`${VST_DIR}`).replace(/\\/g, "/");
    let table = data.map((d) => {
      let _file = d.newFile.replace(root, "");
      let _dir = path.dirname(_file);
      return {
        status: d.status,
        arch: d.arch,
        dir: _dir.split("/")[2],
        creator: _dir.split("/")[3],
        plug: _dir.split("/").splice(4, 999).join(" | "),
        name: path.basename(_file),
      };
    });

    let lastCreator = null;
    let stripes = ["blue", "magenta"];
    let stripeIndex = -1;
    let currentColor = null;
    let reportTable = new Table();
    table.forEach((tr, i) => {
      if (tr.creator !== lastCreator) {
        lastCreator = tr.creator;
        stripeIndex++;
        if (stripeIndex > stripes.length - 1) {
          stripeIndex = 0;
        }
        currentColor = stripes[stripeIndex];
      }
      let color = { color: currentColor };
      if (tr.status.includes("☒")) {
        color = { color: "yellow" };
      } else if (tr.status.includes("✓")) {
        color = { color: currentColor == stripes[0] ? "cyan" : "green" };
      }
      let _tr = tr;
      reportTable.addRow(_tr, color);
    });
    reportTable.printTable();
  }

  const processPlugins = (plugins) => {
    const plug32 = plugins.filter((p) => p.architecture == "32-bit");
    const plug64 = plugins.filter((p) => p.architecture == "64-bit");
    const plugUnknown = plugins.filter((p) => p.architecture == "unknown");

    if (argv.list) {
      listPlugins("32 Bit", plug32, plug64);
      listPlugins("64 Bit", plug64, plug32);
      listPlugins("??????", plugUnknown, []);
    }

    if (argv.sortArch) {
      let report = [];
      plug32.forEach(generateSymlink(VST32Dir, report, "32-bit", plug64));
      plug64.forEach(generateSymlink(VST64Dir, report, "64-bit"));
      printReport(report);
    }
  };

  Promise.all(tableInfo).then(processPlugins);
};

listFiles();
