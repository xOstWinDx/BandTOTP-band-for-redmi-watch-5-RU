const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const target = path.join(root, "src");
const entries = ["app.ux", "manifest.json", "config-watch.json", "common", "pages"];

function copyEntry(name) {
  const source = path.join(root, name);
  const destination = path.join(target, name);

  if (!fs.existsSync(source)) {
    return;
  }

  fs.cpSync(source, destination, {
    recursive: true,
    force: true,
    dereference: true
  });
}

fs.rmSync(target, { recursive: true, force: true });
fs.mkdirSync(target, { recursive: true });
entries.forEach(copyEntry);

console.log("AIoT source prepared in src");
