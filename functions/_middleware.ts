// Cloudflare Pages entry point for the login gate. The logic lives in lib/site-auth.ts.
// Pages runs a root _middleware on every request, including static files.
import { handleAuth } from "../lib/site-auth.ts";

type Context = { request: Request; next(): Promise<Response>; env: Record<string, string | undefined> };

export const onRequest = (context: Context) =>
  handleAuth(context.request, () => context.next(), (key) => context.env[key]);
