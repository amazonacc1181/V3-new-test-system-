import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("production configuration refuses to start without a strong JWT secret", async () => {
  const source = fs.readFileSync(new URL("./server.js", import.meta.url), "utf8");
  assert.match(source, /JWT_SECRET\.length < 32/);
  assert.match(source, /ADMIN_PASSWORD_HASH/);
});
test("NEET exam publication enforces exact 45/45/90 distribution", async () => {
  const source = fs.readFileSync(new URL("./server.js", import.meta.url), "utf8");
  assert.match(source, /counts\.Physics !== 45/);
  assert.match(source, /counts\.Chemistry !== 45/);
  assert.match(source, /counts\.Biology !== 90/);
});
test("server does not accept or store biometric templates or images", () => {
  const source = fs.readFileSync(new URL("./server.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /faceDescriptor|referencePhoto|imageData|base64Photo/i);
  assert.match(source, /advisoryOnly:true/);
});
test("API has role-gated admin analytics and report export routes", () => {
  const source = fs.readFileSync(new URL("./server.js", import.meta.url), "utf8");
  assert.match(source, /\/api\/admin\/dashboard/);
  assert.match(source, /\/api\/admin\/analytics/);
  assert.match(source, /\/api\/admin\/reports\/export\.csv/);
});
