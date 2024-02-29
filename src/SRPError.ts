import { ErrorCode } from "./types";

export class SRPError extends Error {
  constructor(
    public responsible: "client" | "server",
    public code: ErrorCode,
  ) {
    super(
      code === "InvalidPublicEphemeral"
        ? `The ${responsible} sent an invalid public ephemeral`
        : `The ${responsible} provided an invalid session proof`,
    );

    this.name = this.constructor.name;
    Object.setPrototypeOf(this, SRPError.prototype);
  }
}
