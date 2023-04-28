import { CeramicClient } from '@ceramicnetwork/http-client';

const { CERAMIC_API_URL } = process.env;
export const ceramicHttpClient = new CeramicClient(CERAMIC_API_URL);
