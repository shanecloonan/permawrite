import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "Permawrite Public Testnet",
    template: "%s | Permawrite",
  },
  description:
    "Permawrite experimental public testnet — wallet, faucet, boot peers, and live tip.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
