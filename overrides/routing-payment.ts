import { CLEAN_STREAMING_EXCLUSION_SPECS } from "./routing-ai.ts";
import type { RoutingExclusionOverride, RoutingRuleOverride } from "./routing-schema.ts";

/**
 * Curated high-confidence entries for dist/Payment.list covering overseas payment gateways
 * (PayPal, Stripe, Apple Pay, Google Pay, Adyen, Square, Wise, Revolut), overseas commercial
 * and virtual banks (HK / SG / US / UK / EU), card networks (Visa, Mastercard, Amex),
 * overseas brokerages (IBKR, Schwab, Futu, etc.), and payment-exclusive 3DS/checkout risk domains.
 */
export const PAYMENT_FORCE_ENTRIES: readonly RoutingRuleOverride[] = [
  // Overseas Payments, PayPal & Digital Wallets
  ...(
    [
      ["paypal.com", "PayPal global checkout, web wallet, and REST APIs"],
      ["paypalobjects.com", "PayPal static SDKs, checkout assets, and scripts"],
      ["paypal.me", "PayPal peer-to-peer payment links"],
      ["paypal-mktg.com", "PayPal regional marketing and onboarding assets"],
      ["venmo.com", "PayPal Venmo US digital wallet"],
      ["braintreegateway.com", "PayPal Braintree card tokenization gateway"],
      ["braintree-api.com", "PayPal Braintree GraphQL payment API"],
      ["stripe.com", "Stripe global checkout, Elements, Billing, and API"],
      ["stripe.network", "Stripe Radar device fingerprinting and fraud telemetry"],
      ["stripecdn.com", "Stripe static checkout and dashboard CDN"],
      ["link.com", "Stripe Link one-click payment authentication"],
      ["adyen.com", "Adyen global card acquiring and payment gateway"],
      ["adyenpayments.com", "Adyen checkout session endpoint"],
      ["checkout.com", "Checkout.com global payment processor"],
      ["worldpay.com", "Worldpay global merchant card processor"],
      ["paddle.com", "Paddle SaaS merchant-of-record checkout"],
      ["lemonsqueezy.com", "Lemon Squeezy SaaS billing and checkout"],
      ["polar.sh", "Polar open-source developer billing platform"],
      ["gumroad.com", "Gumroad digital creator checkout"],
      ["wise.com", "Wise multi-currency cross-border account and transfers"],
      ["transferwise.com", "Wise legacy API and banking domain"],
      ["revolut.com", "Revolut global digital banking and cards"],
      ["payoneer.com", "Payoneer cross-border settlement platform"],
      ["airwallex.com", "Airwallex cross-border business account and cards"],
      ["mercury.com", "Mercury US startup banking platform"],
      ["brex.com", "Brex corporate card and spend platform"],
      ["ramp.com", "Ramp corporate card and finance platform"],
      ["plaid.com", "Plaid open-banking account linking gateway"],
      ["klarna.com", "Klarna buy-now-pay-later checkout"],
      ["affirm.com", "Affirm installment payment gateway"],
      ["afterpay.com", "Afterpay global checkout"],
      ["squareup.com", "Block Square payment gateway"],
      ["cash.app", "Block Cash App wallet"],
    ] as const
  ).map(
    ([value, rationale]): RoutingRuleOverride => ({
      target: "payment",
      kind: "DOMAIN-SUFFIX",
      value,
      extendedMatching: true,
      rationale,
    }),
  ),
  {
    target: "payment",
    kind: "DOMAIN",
    value: "apple-pay-gateway.apple.com",
    extendedMatching: true,
    rationale: "Apple Pay overseas card tokenization gateway",
  },
  {
    target: "payment",
    kind: "DOMAIN",
    value: "pay.google.com",
    rationale: "Google Pay checkout portal",
  },
  {
    target: "payment",
    kind: "DOMAIN-SUFFIX",
    value: "payments.google.com",
    rationale: "Google Pay billing and merchant profile gateway",
  },
  {
    target: "payment",
    kind: "DOMAIN-KEYWORD",
    value: "stripe",
    rationale: "Stripe checkout and merchant API keyword",
  },
  {
    target: "payment",
    kind: "DOMAIN-SUFFIX",
    value: "paypalbeacon.com",
    rationale: "PayPal dedicated checkout risk and device beacon",
  },

  // Payment-Exclusive 3-D Secure & Card Acquiring Fraud Engines
  ...(
    [
      ["cardinalcommerce.com", "Visa CardinalCommerce 3-D Secure (3DS) card authentication"],
      ["cybersource.com", "Visa CyberSource payment fraud and checkout risk engine"],
      ["accertify.com", "Accertify payment chargeback and fraud screening"],
      ["arcot.com", "Broadcom Arcot 3-D Secure issuer authentication"],
      ["3dsecure.io", "3-D Secure EMVCo verification service"],
    ] as const
  ).map(
    ([value, rationale]): RoutingRuleOverride => ({
      target: "payment",
      kind: "DOMAIN-SUFFIX",
      value,
      extendedMatching: true,
      rationale,
    }),
  ),

  // Overseas Banks, Virtual Banks, Card Networks & Brokerages (HK / SG / US / UK / EU)
  ...(
    [
      ["hsbc.com", "HSBC Group global banking portal"],
      ["hsbc.com.hk", "HSBC Hong Kong personal and Premier banking"],
      ["hsbc.co.uk", "HSBC UK banking portal"],
      ["hsbc.com.sg", "HSBC Singapore banking portal"],
      ["hsbcnet.com", "HSBC corporate and institutional treasury portal"],
      ["hangseng.com", "Hang Seng Bank Hong Kong"],
      ["bochk.com", "Bank of China (Hong Kong) overseas banking"],
      ["za.group", "ZA International financial group"],
      ["zabank.com", "ZA Bank Hong Kong virtual bank"],
      ["mox.com", "Mox Bank Hong Kong virtual bank"],
      ["livi.com.hk", "livi Bank Hong Kong virtual bank"],
      ["livibank.com", "livi Bank Hong Kong mobile API"],
      ["welab.bank", "WeLab Bank Hong Kong virtual bank"],
      ["antbank.hk", "Ant Bank (Hong Kong) virtual bank"],
      ["fusionbank.com", "Fusion Bank Hong Kong virtual bank"],
      ["airstarbank.com", "Airstar Bank Hong Kong virtual bank"],
      ["pao-bank.com", "PAObank Hong Kong virtual bank"],
      ["sc.com", "Standard Chartered global and HK/SG banking"],
      ["dbs.com", "DBS Bank Singapore and Hong Kong"],
      ["dbs.com.sg", "DBS Bank Singapore"],
      ["dbs.com.hk", "DBS Bank Hong Kong"],
      ["ocbc.com", "OCBC Bank Singapore and Hong Kong"],
      ["uobgroup.com", "United Overseas Bank Singapore"],
      ["citi.com", "Citibank US and global consumer banking"],
      ["citibank.com", "Citibank global online banking"],
      ["citibank.com.hk", "Citibank Hong Kong banking"],
      ["citigroup.com", "Citigroup institutional platform"],
      ["chase.com", "JPMorgan Chase US banking and credit cards"],
      ["jpmorgan.com", "J.P. Morgan private and institutional banking"],
      ["jpmorganchase.com", "JPMorgan Chase corporate portal"],
      ["bankofamerica.com", "Bank of America consumer banking"],
      ["bofa.com", "Bank of America mobile and card services"],
      ["wellsfargo.com", "Wells Fargo US banking"],
      ["capitalone.com", "Capital One US banking and cards"],
      ["americanexpress.com", "American Express global card services"],
      ["aexp-static.com", "American Express static security and UI assets"],
      ["discover.com", "Discover card and banking"],
      ["usbank.com", "U.S. Bank consumer banking"],
      ["sofi.com", "SoFi US digital bank and brokerage"],
      ["ally.com", "Ally Bank US online banking"],
      ["chime.com", "Chime US fintech banking"],
      ["barclays.co.uk", "Barclays UK retail banking"],
      ["barclays.com", "Barclays global banking"],
      ["lloydsbank.com", "Lloyds Bank UK"],
      ["natwest.com", "NatWest UK banking"],
      ["monzo.com", "Monzo UK digital bank"],
      ["starlingbank.com", "Starling Bank UK"],
      ["n26.com", "N26 European digital bank"],
      ["bunq.com", "bunq European digital bank"],
      ["visa.com", "Visa global card network and Click to Pay"],
      ["mastercard.com", "Mastercard global card network"],
      ["interactivebrokers.com", "Interactive Brokers global brokerage"],
      ["ibkr.com", "Interactive Brokers Client Portal and TWS API"],
      ["schwab.com", "Charles Schwab US and International brokerage"],
      ["fidelity.com", "Fidelity Investments brokerage"],
      ["robinhood.com", "Robinhood brokerage"],
      ["etrade.com", "E*TRADE brokerage"],
      ["firstrade.com", "Firstrade US brokerage"],
      ["tastytrade.com", "tastytrade US options brokerage"],
      ["webull.com", "Webull overseas brokerage"],
      ["futuhk.com", "Futu Bull Hong Kong brokerage"],
      ["moomoo.com", "Moomoo overseas brokerage"],
      ["longbridgeapp.com", "Longbridge Hong Kong/Singapore brokerage"],
      ["tigerbrokers.com", "Tiger Brokers overseas brokerage"],
    ] as const
  ).map(
    ([value, rationale]): RoutingRuleOverride => ({
      target: "payment",
      kind: "DOMAIN-SUFFIX",
      value,
      extendedMatching: true,
      rationale,
    }),
  ),
];

export const PAYMENT_EXCLUDE_ENTRIES: readonly RoutingExclusionOverride[] =
  CLEAN_STREAMING_EXCLUSION_SPECS.map(([value, rationale]) => ({
    target: "payment",
    kind: "DOMAIN-SUFFIX",
    value,
    rationale,
  }));
