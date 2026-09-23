import { requireRole } from "../lib/auth/middleware.server";
export async function POST(req: Request) {
  await requireRole(req, "admin");
  return new Response("ok");
}
