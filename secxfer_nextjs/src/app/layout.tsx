import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

export const metadata: Metadata = {
  title: "SecXfer — Zero-Trust Encrypted File Transfer",
  description: "Post-Quantum, Zero-Trust, End-to-End Encrypted file exchange. Built with Django, Next.js, X3DH and AES-256-GCM.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${inter.variable} h-full antialiased`}>
      <body className="min-h-full flex flex-col bg-[#080c14]">{children}</body>
    </html>
  );
}
