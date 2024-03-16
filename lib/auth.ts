import { PrismaAdapter } from "@auth/prisma-adapter";
import { NextAuthOptions } from "next-auth";
import db from "./db";
import CredentialsProvider from "next-auth/providers/credentials";
import { compare } from "bcrypt";
import { Adapter } from "next-auth/adapters";

const options: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email", placeholder: "jsmith@acme.me" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials.password) return null;
        const user = await db.user.findUnique({
          where: {
            email: credentials.email,
          },
        });
        if (!user) return null;
        const passwordMatch = await compare(
          credentials.password,
          user.hashedPassword!
        );
        if (!passwordMatch) return null;
        return { id: user.id, username: user.name, email: user.email };
      },
    }),
  ],
  secret: process.env.NEXTAUTH_SECRET,
  adapter: PrismaAdapter(db) as Adapter,
  session: {
    strategy: "jwt",
    //   maxAge: 30 * 24 * 60 * 60,
  },
};
