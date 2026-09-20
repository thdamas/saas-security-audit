import Stripe from 'stripe'
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)

export async function POST(req: Request) {
  const sig = req.headers.get('stripe-signature')!
  const event = await stripe.webhooks.constructEventAsync(await req.text(), sig, process.env.STRIPE_WEBHOOK_SECRET!)
  return new Response(event.type)
}
