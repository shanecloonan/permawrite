import { redirect } from "next/navigation";

/** Standalone app root → /testnet page. */
export default function Home() {
  redirect("/testnet");
}
