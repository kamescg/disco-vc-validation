// eslint-disable-next-line max-classes-per-file
export class Missing712ProofException extends Error {
  constructor() {
    super('Missing proof');
  }
}

export class Missing712DomainException extends Error {
  constructor() {
    super('Missing EIP712 domain');
  }
}

export class SignatureMismatchException extends Error {
  constructor(did: string, issuer: string) {
    super(`Signature mismatch: ${did} !== ${issuer}`);
  }
}

export class ApplicationException extends Error {
  constructor(msg: string, code: string) {
    super(msg);
    // @ts-ignore
    this.code = code;
  }
}

export async function logError(err: any) {
  console.error(err);
}
