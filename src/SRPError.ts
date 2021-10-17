import { Entity, ErrorCode } from "./types";

export class SRPError extends Error {
  constructor(public entity: Entity, public code: ErrorCode) {
    super(
      code === "invalidPublicEphemeral"
        ? `The ${entity} sent an invalid public ephemeral`
        : `${entity} provided session proof is invalid`,
    );

    this.name = this.constructor.name;
    Object.setPrototypeOf(this, SRPError.prototype);
  }
}
