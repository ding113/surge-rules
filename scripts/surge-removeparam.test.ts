import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const scriptSource = readFileSync(resolve(import.meta.dir, "surge-removeparam.js"), "utf8");

function runSurgeRemoveParam(url: string, argument: string): Record<string, unknown> {
  let result: Record<string, unknown> | undefined;
  const done = (obj?: Record<string, unknown>) => {
    result = obj ?? {};
  };
  const runner = new Function("$request", "$argument", "$done", scriptSource);
  runner({ url }, argument, done);
  if (result === undefined) {
    throw new Error("Script failed to call $done()");
  }
  return result;
}

describe("surge-removeparam runtime script", () => {
  const arg = "*=utm_source|utm_medium|fbclid;bilibili.com=spm_id_from|vd_source";

  it("removes global and host-scoped tracking params while keeping non-tracking params and fragment", () => {
    const out = runSurgeRemoveParam(
      "https://www.bilibili.com/video/BV1xx411c7mD?p=2&spm_id_from=333.1007&utm_source=share&vd_source=abc#reply",
      arg,
    );
    expect(out).toEqual({
      url: "https://www.bilibili.com/video/BV1xx411c7mD?p=2#reply",
    });
  });

  it("removes the question mark completely when all query params are stripped", () => {
    const out = runSurgeRemoveParam("https://example.org/post?utm_source=x&fbclid=123#top", arg);
    expect(out).toEqual({
      url: "https://example.org/post#top",
    });
  });

  it("calls $done({}) untouched when no configured parameter matches", () => {
    const out = runSurgeRemoveParam("https://example.org/search?q=surge%20rules&page=1", arg);
    expect(out).toEqual({});
  });

  it("preserves percent encoding and does not touch spm_id_from outside bilibili.com", () => {
    const out = runSurgeRemoveParam(
      "https://other.example.net/item?name=hello%20world&spm_id_from=keep&utm_medium=rss",
      arg,
    );
    expect(out).toEqual({
      url: "https://other.example.net/item?name=hello%20world&spm_id_from=keep",
    });
  });

  it("is strictly idempotent", () => {
    const first = runSurgeRemoveParam(
      "https://m.bilibili.com/v?utm_source=a&spm_id_from=b&cid=42",
      arg,
    );
    const cleaned = String(first.url);
    const second = runSurgeRemoveParam(cleaned, arg);
    expect(second).toEqual({});
  });

  it("property: preserves benign params & fragments byte-for-byte, strips matching params, and is idempotent across 300 generated URLs", () => {
    let seed = 0x5eed1234;
    const nextRand = () => {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      return seed;
    };
    const hosts = [
      "www.bilibili.com",
      "m.bilibili.com",
      "example.org",
      "shop.example.net",
      "news.sub.example.com",
    ];
    const benignPairs: Array<[string, string]> = [
      ["q", "surge%20rules"],
      ["page", "2"],
      ["sort", "desc"],
      ["cid", "987654"],
      ["token", "abc%2Bdef%3D1"],
      ["lang", "zh-CN"],
    ];
    const globalTrackers = ["utm_source", "utm_medium", "fbclid"];
    const biliTrackers = ["spm_id_from", "vd_source"];

    for (let i = 0; i < 300; i++) {
      const host = hosts[nextRand() % hosts.length] ?? "example.org";
      const isBili = host === "bilibili.com" || host.endsWith(".bilibili.com");
      const queryParts: string[] = [];
      const expectedKept: string[] = [];
      let shouldRemoveAny = false;

      const count = 1 + (nextRand() % 8);
      for (let j = 0; j < count; j++) {
        const roll = nextRand() % 3;
        if (roll === 0) {
          const k = globalTrackers[nextRand() % globalTrackers.length] ?? "utm_source";
          const val = `t${nextRand() % 1000}`;
          queryParts.push(`${k}=${val}`);
          shouldRemoveAny = true;
        } else if (roll === 1) {
          const k = biliTrackers[nextRand() % biliTrackers.length] ?? "spm_id_from";
          const val = `b${nextRand() % 1000}`;
          const kv = `${k}=${val}`;
          queryParts.push(kv);
          if (isBili) {
            shouldRemoveAny = true;
          } else {
            expectedKept.push(kv);
          }
        } else {
          const pair = benignPairs[nextRand() % benignPairs.length] ?? ["page", "1"];
          const kv = `${pair[0]}=${pair[1]}_${j}`;
          queryParts.push(kv);
          expectedKept.push(kv);
        }
      }

      const fragment = nextRand() % 2 === 0 ? `#sec-${nextRand() % 50}` : "";
      const path = `/item/${nextRand() % 99}`;
      const rawUrl = `https://${host}${path}?${queryParts.join("&")}${fragment}`;
      const first = runSurgeRemoveParam(rawUrl, arg);

      if (!shouldRemoveAny) {
        expect(first).toEqual({});
        continue;
      }

      const expectedQuery = expectedKept.length > 0 ? `?${expectedKept.join("&")}` : "";
      const expectedUrl = `https://${host}${path}${expectedQuery}${fragment}`;
      expect(first).toEqual({ url: expectedUrl });

      // Idempotency invariant: second pass leaves cleaned URL untouched
      const second = runSurgeRemoveParam(String(first.url), arg);
      expect(second).toEqual({});
    }
  });

  it("reuses parsed cache on identical $argument and invalidates when $argument changes", () => {
    const globalObj = globalThis as Record<string, unknown>;
    delete globalObj.__surgeRemoveParamCache;

    const firstOut = runSurgeRemoveParam(
      "https://sub.bilibili.com/v?utm_source=x&spm_id_from=y&keep=1",
      arg,
    );
    expect(firstOut).toEqual({ url: "https://sub.bilibili.com/v?keep=1" });

    const firstCache = globalObj.__surgeRemoveParamCache as
      | { arg: string; globalSet: Set<string>; scopedMap: Map<string, Set<string>> }
      | undefined;
    expect(firstCache).toBeDefined();
    expect(firstCache?.arg).toBe(arg);
    expect(firstCache?.globalSet.has("utm_source")).toBe(true);
    expect(firstCache?.scopedMap.get("bilibili.com")?.has("spm_id_from")).toBe(true);

    // Same $argument reuses the exact cached object instance
    const secondOut = runSurgeRemoveParam("https://sub.bilibili.com/v?utm_medium=z&keep=2", arg);
    expect(secondOut).toEqual({ url: "https://sub.bilibili.com/v?keep=2" });
    expect(globalObj.__surgeRemoveParamCache).toBe(firstCache);

    // Label-boundary safety: lookalike sibling domain must not match scoped rules
    const lookalikeOut = runSurgeRemoveParam(
      "https://notbilibili.com/v?spm_id_from=keep&keep=3",
      arg,
    );
    expect(lookalikeOut).toEqual({});

    // Updated $argument invalidates cache and switches active rules immediately
    const updatedArg = "notbilibili.com=spm_id_from;sub.example.com=ref_id";
    const thirdOut = runSurgeRemoveParam(
      "https://a.b.notbilibili.com/v?utm_source=keep&spm_id_from=drop&keep=4",
      updatedArg,
    );
    expect(thirdOut).toEqual({ url: "https://a.b.notbilibili.com/v?utm_source=keep&keep=4" });
    const secondCache = globalObj.__surgeRemoveParamCache as
      | { arg: string; globalSet: Set<string>; scopedMap: Map<string, Set<string>> }
      | undefined;
    expect(secondCache).toBeDefined();
    expect(secondCache).not.toBe(firstCache);
    expect(secondCache?.arg).toBe(updatedArg);
    expect(secondCache?.globalSet.size).toBe(0);
    expect(secondCache?.scopedMap.has("sub.example.com")).toBe(true);
  });
});
