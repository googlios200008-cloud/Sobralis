// Contract only: no provider, checkout route, fiscal receipt or money movement exists.
export type CheckoutRequest = { userId:string; plan:'PRO'; returnUrl:string; idempotencyKey:string };
export type CheckoutSession = { providerPaymentId:string; redirectUrl:string };
export type VerifiedPaymentEvent = { providerEventId:string; providerPaymentId:string; status:'succeeded'|'canceled'|'refunded' };
export interface PaymentProvider {
  createCheckout(request: CheckoutRequest): Promise<CheckoutSession>;
  verifyWebhook(rawBody: Uint8Array, headers: Readonly<Record<string,string>>): Promise<VerifiedPaymentEvent>;
}
