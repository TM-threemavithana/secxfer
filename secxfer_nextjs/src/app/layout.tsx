import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecXfer — Zero-Trust Encrypted File Transfer",
  description: "Post-Quantum, Zero-Trust, End-to-End Encrypted file exchange. Built with Django, Next.js, X3DH and AES-256-GCM.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col bg-[#080c14]">{children}</body>
    </html>
  );
}
