import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const scriptSource = readFileSync(resolve(import.meta.dir, "surge-adguard.js"), "utf8");

function runSurgeAdguard(body: unknown, argument: string): Record<string, unknown> {
  let result: Record<string, unknown> | undefined;
  const done = (obj?: Record<string, unknown>) => {
    result = obj ?? {};
  };
  const runner = new Function("$response", "$argument", "$done", scriptSource);
  runner({ body }, argument, done);
  if (result === undefined) {
    throw new Error("Script failed to call $done()");
  }
  return result;
}

function encodeArg(ops: unknown): string {
  return `u:${encodeURIComponent(JSON.stringify(ops))}`;
}

describe("surge-adguard runtime script", () => {
  it("executes $replace with multiline [\\s\\S], capture groups, spaces, and empty replacements", () => {
    const arg = encodeArg([
      { op: "replace", pat: "adsSrc='[\\s\\S]*?';", rep: "adsSrc='';" },
      { op: "replace", pat: "(\\.onerror=\\(\\)\\=>\\{x\\()!0(\\);)", rep: "$1!1$2" },
      { op: "replace", pat: 'goto\\("/blk"\\);', rep: "" },
    ]);
    const input =
      "const a=1;\nadsSrc='https://ad.example/1.js\nline2';\nimg.onerror=()=>{x(!0);};goto(\"/blk\");";
    const out = runSurgeAdguard(input, arg);
    expect(out).toEqual({
      body: "const a=1;\nadsSrc='';\nimg.onerror=()=>{x(!1);};",
    });
    // Idempotent second pass
    expect(runSurgeAdguard(out.body, arg)).toEqual({});
  });

  it("prunes matching HLS ($hls) ad segments while keeping playlist headers and content segments intact", () => {
    const arg = encodeArg([
      { op: "hls", pat: "#UPLYNK-SEGMENT:.*,ad", flags: "t" }, // non-JS flag `t` must be safely ignored
      { op: "hls", pat: "https://prism-ads-cdn\\.a2d\\.tv/" },
    ]);
    const m3u8 = [
      "#EXTM3U",
      "#EXT-X-VERSION:3",
      "#EXT-X-TARGETDURATION:6",
      "#EXT-X-MEDIA-SEQUENCE:100",
      "#UPLYNK-SEGMENT:100,ad",
      "#EXTINF:6.000,",
      "https://cdn.uplynk.com/seg100.ts",
      "#EXTINF:6.000,",
      "https://prism-ads-cdn.a2d.tv/preroll/seg1.ts",
      "#UPLYNK-SEGMENT:101,segment",
      "#EXTINF:6.000,",
      "https://cdn.uplynk.com/content101.ts",
      "#EXT-X-ENDLIST",
    ].join("\n");

    const out = runSurgeAdguard(m3u8, arg);
    expect(out).toEqual({
      body: [
        "#EXTM3U",
        "#EXT-X-VERSION:3",
        "#EXT-X-TARGETDURATION:6",
        "#EXT-X-MEDIA-SEQUENCE:100",
        "#UPLYNK-SEGMENT:101,segment",
        "#EXTINF:6.000,",
        "https://cdn.uplynk.com/content101.ts",
        "#EXT-X-ENDLIST",
      ].join("\n"),
    });
    expect(runSurgeAdguard(out.body, arg)).toEqual({});
  });

  it("prunes MPEG-DASH ($xmlprune) ad Periods and @start attributes using XPath union snapshot semantics", () => {
    const amazonRule = encodeArg([
      {
        op: "xmlprune",
        expr: '//*[name()="Period"][.//*[@value="Ad"]] | //*[name()="Period"]/@start[boolean(//*[@value="Ad"])]',
      },
    ]);
    const mpdWithAd = [
      '<MPD type="static">',
      '  <Period id="p0" start="PT0S"><SupplementalProperty schemeIdUri="urn:ad" value="Ad"/></Period>',
      '  <Period id="p1" start="PT30S" duration="PT600S"><AdaptationSet mimeType="video/mp4"/></Period>',
      "</MPD>",
    ].join("\n");

    const cleaned = runSurgeAdguard(mpdWithAd, amazonRule);
    expect(cleaned).toEqual({
      body: [
        '<MPD type="static">',
        "  ",
        '  <Period id="p1" duration="PT600S"><AdaptationSet mimeType="video/mp4"/></Period>',
        "</MPD>",
      ].join("\n"),
    });

    // When no Ad Period exists, @start on content Period must NOT be removed
    const mpdWithoutAd = [
      '<MPD type="static">',
      '  <Period id="p1" start="PT0S" duration="PT600S"><AdaptationSet mimeType="video/mp4"/></Period>',
      "</MPD>",
    ].join("\n");
    expect(runSurgeAdguard(mpdWithoutAd, amazonRule)).toEqual({});

    // Hulu contains(@id, 'ad-') rule
    const huluRule = encodeArg([{ op: "xmlprune", expr: "/MPD/Period[contains(@id,'ad-')]" }]);
    const huluMpd =
      '<MPD><Period id="pre-ad-01"><BaseURL>ad</BaseURL></Period><Period id="main-01"><BaseURL>ok</BaseURL></Period></MPD>';
    expect(runSurgeAdguard(huluMpd, huluRule)).toEqual({
      body: '<MPD><Period id="main-01"><BaseURL>ok</BaseURL></Period></MPD>',
    });
  });

  it("evaluates extended AdGuard $jsonprune rules (YouTube multi-key, X/Twitter key-substr & has, key-eq, bracketed keys)", () => {
    const ytArg = encodeArg([
      { op: "jsonprune", expr: "$..[adPlacements, adSlots, playerAds]" },
      {
        op: "jsonprune",
        expr: '$.entries[?(has "$..command.reelWatchEndpoint.adClientParams.isAd")]',
      },
    ]);
    const ytPayload = JSON.stringify({
      videoDetails: { videoId: "abc" },
      adPlacements: [{ id: 1 }],
      nested: { playerAds: [{ id: 2 }], adSlots: [{ id: 3 }], keep: true },
      entries: [
        { command: { reelWatchEndpoint: { videoId: "reel1" } } },
        { command: { reelWatchEndpoint: { adClientParams: { isAd: true } } } },
      ],
    });
    const ytOut = runSurgeAdguard(ytPayload, ytArg);
    expect(JSON.parse(String(ytOut.body))).toEqual({
      videoDetails: { videoId: "abc" },
      nested: { keep: true },
      entries: [{ command: { reelWatchEndpoint: { videoId: "reel1" } } }],
    });

    // X / Twitter HomeTimeline & TweetDetail rules
    const xArg = encodeArg([
      {
        op: "jsonprune",
        expr: "$.data.home.home_timeline_urt.instructions..entries..[?(key-substr 'entryId' 'promoted-tweet-')]",
      },
      {
        op: "jsonprune",
        expr: '$.data.threaded_conversation_with_injections_v2.instructions..entries.[?(has "$.content.items..item.itemContent.promotedMetadata.advertiser_results")]',
      },
      {
        op: "jsonprune",
        expr: '$.data.publicDynamicConfig.campaign.feed.*..[?(key-eq "$.isAd" true)]',
      },
      {
        op: "jsonprune",
        expr: '$.configs["ConsumptionPage/gallery_default"].properties..interstitialNativeAds',
      },
    ]);
    const xPayload = JSON.stringify({
      data: {
        home: {
          home_timeline_urt: {
            instructions: [
              {
                entries: [
                  { entryId: "tweet-100", text: "real" },
                  { entryId: "promoted-tweet-999", text: "ad" },
                ],
              },
            ],
          },
        },
        threaded_conversation_with_injections_v2: {
          instructions: [
            {
              entries: [
                {
                  entryId: "conv-ad",
                  content: {
                    items: [
                      { item: { itemContent: { promotedMetadata: { advertiser_results: {} } } } },
                    ],
                  },
                },
                {
                  entryId: "conv-real",
                  content: { items: [{ item: { itemContent: { tweet: "hello" } } }] },
                },
              ],
            },
          ],
        },
        publicDynamicConfig: {
          campaign: {
            feed: {
              slotA: [
                { id: 1, isAd: true },
                { id: 2, isAd: false },
              ],
            },
          },
        },
      },
      configs: {
        "ConsumptionPage/gallery_default": {
          properties: {
            nested: { interstitialNativeAds: { enabled: true }, keepBanner: false },
          },
        },
      },
    });
    const xOut = runSurgeAdguard(xPayload, xArg);
    expect(JSON.parse(String(xOut.body))).toEqual({
      data: {
        home: {
          home_timeline_urt: {
            instructions: [{ entries: [{ entryId: "tweet-100", text: "real" }] }],
          },
        },
        threaded_conversation_with_injections_v2: {
          instructions: [
            {
              entries: [
                {
                  entryId: "conv-real",
                  content: { items: [{ item: { itemContent: { tweet: "hello" } } }] },
                },
              ],
            },
          ],
        },
        publicDynamicConfig: {
          campaign: {
            feed: {
              slotA: [{ id: 2, isAd: false }],
            },
          },
        },
      },
      configs: {
        "ConsumptionPage/gallery_default": {
          properties: {
            nested: { keepBanner: false },
          },
        },
      },
    });
  });

  it("fails open ($done({})) on malformed JSON, empty body, or non-matching payloads", () => {
    const arg = encodeArg([{ op: "jsonprune", expr: "$..adSlots" }]);
    expect(runSurgeAdguard("", arg)).toEqual({});
    expect(runSurgeAdguard(undefined, arg)).toEqual({});
    expect(runSurgeAdguard("<html>not json</html>", arg)).toEqual({});
    expect(runSurgeAdguard("{broken json", arg)).toEqual({});
    expect(runSurgeAdguard('{"ok":1}', arg)).toEqual({});
  });

  it("property: $jsonprune removes all targeted ad keys/predicates, preserves benign fields, and is strictly idempotent across 200 generated payloads", () => {
    let seed = 0x9e3779b9;
    const nextRand = () => {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      return seed;
    };
    const arg = encodeArg([
      { op: "jsonprune", expr: "$..[adPlacements, playerAds]" },
      { op: "jsonprune", expr: "$.feed..[?(key-substr 'entryId' 'promoted-')]" },
    ]);

    for (let i = 0; i < 200; i++) {
      const realCount = 1 + (nextRand() % 5);
      const adCount = nextRand() % 4;
      const includeTopAdKey = nextRand() % 2 === 0;
      const includeNestedAdKey = nextRand() % 2 === 0;

      const feed: Array<{ entryId: string; seq: number }> = [];
      const expectedFeed: Array<{ entryId: string; seq: number }> = [];
      for (let r = 0; r < realCount; r++) {
        const item = { entryId: `post-${i}-${r}`, seq: r };
        feed.push(item);
        expectedFeed.push(item);
      }
      for (let a = 0; a < adCount; a++) {
        feed.splice(nextRand() % (feed.length + 1), 0, {
          entryId: `promoted-${i}-${a}`,
          seq: 100 + a,
        });
      }

      const payloadObj: Record<string, unknown> = {
        meta: { page: i, ok: true },
        feed,
        nested: {
          title: `item-${i}`,
          ...(includeNestedAdKey ? { playerAds: [{ slot: i }] } : {}),
        },
        ...(includeTopAdKey ? { adPlacements: [1, 2] } : {}),
      };

      const raw = JSON.stringify(payloadObj);
      const first = runSurgeAdguard(raw, arg);
      const shouldMutate = adCount > 0 || includeTopAdKey || includeNestedAdKey;

      if (!shouldMutate) {
        expect(first).toEqual({});
        continue;
      }

      const parsed = JSON.parse(String(first.body));
      expect(parsed).toEqual({
        meta: { page: i, ok: true },
        feed: expectedFeed,
        nested: { title: `item-${i}` },
      });
      // Idempotency invariant
      expect(runSurgeAdguard(first.body, arg)).toEqual({});
    }
  });
});
