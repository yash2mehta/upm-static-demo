// Netlify entry point for the login gate. The logic lives in lib/site-auth.ts.
import { handleAuth } from "../../lib/site-auth.ts";

declare const Netlify: { env: { get(key: string): string | undefined } };
type Context = { next(): Promise<Response> };

export default (request: Request, context: Context) =>
  handleAuth(request, () => context.next(), (key) => Netlify.env.get(key));

export const config = { path: "/*" };
