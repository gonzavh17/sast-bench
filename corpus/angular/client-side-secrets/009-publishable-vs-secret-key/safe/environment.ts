export const environment = {
  production: true,
  apiBaseUrl: 'https://api.example.com',
  // Publishable key: it is meant to live in the browser. It only allows
  // tokenizing a card; on its own it cannot read or charge anything.
  stripeKey: 'pk_live_EXAMPLE_NOT_A_REAL_KEY_000000',
};
