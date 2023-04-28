import { getResolver } from '@ceramicnetwork/3id-did-resolver';
import { Caip10Link } from '@ceramicnetwork/stream-caip10-link';
import {
  recoverTypedSignature,
  SignTypedDataVersion,
} from '@metamask/eth-sig-util';
import { decodeJWT, verifyJWS } from 'did-jwt';
import { Resolver } from 'did-resolver';

import {
  Missing712DomainException,
  Missing712ProofException,
  SignatureMismatchException,
} from './errors';

import { ceramicHttpClient } from './ceramic';
import { ACCOUNT_ID_SUFFIX } from './constants';

const JWT_REGEX = /^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/;

export async function retrieveDidDocument(did: string) {
  const threeidresolver = getResolver(ceramicHttpClient);
  const resolver = new Resolver(threeidresolver);
  const doc = await resolver.resolve(did);

  return doc;
}

export async function verifyJwtVc(vc: string) {
  const TypedData = JSON.parse(vc);
  const decoded = decodeJWT(TypedData.proof.jwt).payload;
  if (!decoded || !decoded?.issuer) throw new Error('Decoding JWT');
  const issuer =
    typeof decoded.issuer === 'string' ? decoded.issuer : decoded.issuer.id;
  const doc = await retrieveDidDocument(issuer);
  if (!doc.didDocument || !doc.didDocument.verificationMethod)
    throw new Error('Could not fetch did doc');

  const verified = await verifyJWS(
    TypedData.proof.jwt,
    doc.didDocument?.verificationMethod!
  );
  return !!verified;
}

export async function verify712Vc(vc: string) {
  try {
    const TypedData = JSON.parse(vc);
    if (!TypedData.proof || !TypedData.proof.proofValue)
      throw new Missing712ProofException();
    if (
      !TypedData.proof.eip712Domain ||
      !TypedData.proof.eip712Domain.messageSchema ||
      !TypedData.proof.eip712Domain.domain
    )
      throw new Missing712DomainException();

    const { proof, ...signingInput } = TypedData;
    const { proofValue, eip712Domain, ...verifyInputProof } = proof;
    const verificationMessage = {
      ...signingInput,
      proof: verifyInputProof,
    };

    const objectToVerify = {
      message: verificationMessage,
      domain: eip712Domain.domain,
      types: eip712Domain.messageSchema,
      primaryType: eip712Domain.primaryType,
    };

    const recovered = recoverTypedSignature({
      data: objectToVerify,
      signature: proofValue,
      version: SignTypedDataVersion.V4,
    });

    // Get did from address using CAIP 10
    const { did } = await Caip10Link.fromAccount(
      ceramicHttpClient,
      recovered + ACCOUNT_ID_SUFFIX
    );

    if (did === signingInput.issuer.id) {
      return TypedData;
    }
    // @ts-ignore
    throw new SignatureMismatchException(did, signingInput.issuer.id);
  } catch (e: any) {
    console.log(e);
    throw e;
  }
}

export async function verify(verifiableCredential: string) {
  const TypedData = JSON.parse(verifiableCredential);
  return TypedData?.proof?.jwt?.match(JWT_REGEX)
    ? verifyJwtVc(verifiableCredential)
    : verify712Vc(verifiableCredential);
}
