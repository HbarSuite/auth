import { IAuth, Auth } from '@hsuite/auth-types'
import { Inject, Injectable, Optional } from '@nestjs/common'
import { LedgerId, PrivateKey, PublicKey } from '@hashgraph/sdk'
import * as crypto from 'crypto'
import * as lodash from 'lodash'
import { SmartConfigService } from '@hsuite/smart-config'
import { ISmartNetwork } from '@hsuite/smart-network-types'
import { ClientService } from '@hsuite/client'
import { AccountsService } from '@hsuite/mirrors'
import { IpfsService } from '@hsuite/ipfs'
/**
 * Service for handling Web3 authentication operations.
 * 
 * @description
 * This service provides functionality for Web3 wallet-based authentication including:
 * - Token generation and validation
 * - Signature verification
 * - Wallet validation
 * - Token gate information fetching
 * - Login processing
 */
@Injectable()
export class AuthWeb3Service {
    /** Current Hashgraph network environment */
    private environment: LedgerId;

    /**
     * Creates an instance of AuthWeb3Service.
     * 
     * @param authWeb3Options - Configuration options for Web3 authentication
     * @param jwtService - Service for JWT operations
     * @param smartConfigService - Service for accessing configuration values
     * @param ipfsService - Service for IPFS operations
     * @param accountsService - Service for accounts operations
     */
    constructor(
        @Inject('authWeb3Options') private readonly authWeb3Options: IAuth.IConfiguration.IWeb3.IOptions & IAuth.IConfiguration.IOptions,
        @Inject('JwtAuthService') private readonly jwtService,
        private smartConfigService: SmartConfigService,
        private readonly ipfsService: IpfsService,
        @Optional() private readonly clientService: ClientService,
        @Optional() private readonly accountsService: AccountsService
    ) {
        // Set environment and base URL based on network
        this.environment = LedgerId.fromString(this.smartConfigService.getEnvironment());
    }

    /**
     * Gets the operator account ID.
     * 
     * @returns The operator account ID as a string
     */
    getOperatorId(): string {
        return this.authWeb3Options.operator.accountId;
    }

    /**
     * Generates a random token for authentication.
     * 
     * @returns A randomly generated 64-byte hex token
     */
    generateToken(): string {
        var token = crypto.randomBytes(64).toString('hex');
        return token;
    }

    /**
     * Validates a wallet based on the provided signin payload.
     * 
     * @param payload - The signin payload containing signature and operator info
     * @returns Promise resolving to login response or null if validation fails
     */
    async validateWallet(payload: Auth.Credentials.Web3.Request.Signin.Login): Promise<IAuth.ICredentials.IWeb3.IResponse.ILogin | null> {
        return new Promise(async(resolve, reject) => {
            try {
                let isValid = await this.validateSignature(payload.signedData, payload.operator);
                if(isValid) {
                    try {
                        let session = {
                            walletId: payload.operator.accountId,
                            publicKey: payload.operator.publicKey,
                            balance: await this.fetchTokenGateInfos(payload.operator.accountId)
                        };
            
                        resolve({
                            session: session,
                            operator: {
                                accountId: this.authWeb3Options.operator.accountId,
                                publicKey: this.authWeb3Options.operator.publicKey.toString(),
                                url: this.authWeb3Options.operator.url,
                                nft: {
                                    id: null,
                                    serialNumber: null
                                }
                            },
                            accessToken: this.jwtService.sign(session)
                        });
                    } catch(error) {
                        resolve(null);
                    }
                } else {
                    resolve(null);
                }
            } catch(error) {
                reject(error);
            }
        });
    }

    /**
     * Fetches token gate information for a given wallet address.
     * 
     * @param wallet - The wallet address to fetch NFT information for
     * @returns Promise resolving to token gate information including NFT balances
     */
    private fetchTokenGateInfos(wallet: string): Promise<any> {
        return new Promise(async(resolve, reject) => {
            try {
                let nftsBalance = null;
            
                if(this.authWeb3Options.tokenGateOptions.enabled) {
                    let nfts = this.authWeb3Options.tokenGateOptions
                        .roles.filter(role => role.tokenId != null)
                        .map(role => role.tokenId);
                    
                    if(this.accountsService) {
                        let nftBalancePromises = nfts.map(nft => this.accountsService.getNfts({
                            idOrAliasOrEvmAddress: wallet,
                            tokenId: nft,
                            limit: 1
                        }));

                        let nftBalanceResponses = await Promise.all(nftBalancePromises);
                        nftsBalance = nftBalanceResponses.map(nft => nft.nfts).flat();
                    } else {
                        let nftBalancePromises = nfts.map(nft => this.clientService.axios.get(
                            `mirrors/accounts/${wallet}/nfts`,
                            {
                                params: {
                                    'token.id': nft,
                                    'limit': 1
                                }
                            }
                        ));

                        let nftBalanceResponses = await Promise.all(nftBalancePromises);
                        nftsBalance = nftBalanceResponses.map(nft => nft.data.nfts).flat();
                    }

                    let nftMetadatasPromises = nftsBalance.map(nft => this.ipfsService.getMetadata(nft.metadata));
                    let nftMetadatas = await Promise.all(nftMetadatasPromises);
                    nftsBalance = nftsBalance.map((nft, index) => {
                        nft.metadata = nftMetadatas[index];
                        nft.role = this.authWeb3Options.tokenGateOptions.roles.find(role => role.tokenId == nft.token_id)?.role;
                        return nft;
                    });
                }

                 resolve(nftsBalance);
            } catch(error) {
                reject(error);
            }
        })
    }

    /**
     * Performs the login operation for a validated user.
     * 
     * @param user - The validated user information
     * @param payload - The login request payload
     * @returns Promise resolving to the login response
     */
    async login(
        user: IAuth.ICredentials.IWeb3.IResponse.ILogin, 
        payload: IAuth.ICredentials.IWeb3.IRequest.ISignin.ILogin
    ): Promise<IAuth.ICredentials.IWeb3.IResponse.ILogin> {
        return new Promise(async(resolve, reject) => {
            try {
                resolve(user);
            } catch(error) {
                reject(error);
            }         
        })
    }

    /**
     * Validates the signature of signed authentication data.
     * 
     * @param signedData - The signed data to validate
     * @param operator - The operator information containing public key
     * @returns Promise resolving to boolean indicating signature validity
     */
    async validateSignature(signedData: any, operator: ISmartNetwork.IOperator.IEntity): Promise<boolean> {
        return new Promise(async (resolve, reject) => {
            try {
                let originalUserSignedPayload = lodash.cloneDeep(signedData.signedPayload);

                if(lodash.isString(signedData.signedPayload)) {
                    signedData.signedPayload = JSON.parse(signedData.signedPayload.replace(/^[^{]+|[^}]+$/g,''))
                }

                if(signedData.signedPayload) {
                    let serverSignature: any = Object.entries(signedData.signedPayload.serverSignature).map(([key, value]) => value);
                    signedData.signedPayload.serverSignature = new Uint8Array(serverSignature);
    
                    let serverKeyVerified = this.verifyData(
                        signedData.signedPayload.originalPayload,
                        this.authWeb3Options.operator.publicKey,
                        new Uint8Array(serverSignature)
                    );
    
                    let userSignature: any = null;
    
                    if (signedData.userSignature.type == 'Buffer') {
                        userSignature = signedData.userSignature.data;
                    } else {
                        userSignature = Object.entries(signedData.userSignature).map(([key, value]) => value);
                    }
    
                    let userKeyVerified = this.verifyData(
                        originalUserSignedPayload,
                        operator.publicKey,
                        new Uint8Array(userSignature)
                    );
    
                    resolve(serverKeyVerified && userKeyVerified);
                } else {
                    reject(new Error('Invalid signed data'));
                }
            } catch (error) {
                reject(error);
            }
        });
    }

    /**
     * Signs authentication data with the operator's private key.
     * 
     * @param data - The authentication payload to sign
     * @returns The signed data with signature and server account
     */
    signData(data: IAuth.ICredentials.IWeb3.IRequest.IAuthentication.IPayload): 
    IAuth.ICredentials.IWeb3.IRequest.IAuthentication.ISignedData {
        const privateKey = PrivateKey.fromString(this.authWeb3Options.operator.privateKey);
        let bytes = new Uint8Array(Buffer.from(JSON.stringify(data)));
        let signature = privateKey.sign(bytes);

        return { 
            signature: signature, 
            serverSigningAccount: this.authWeb3Options.operator.accountId 
        };
    }

    /**
     * Verifies the signature of data using a public key.
     * 
     * @param data - The data to verify
     * @param publicKey - The public key to use for verification
     * @param signature - The signature to verify
     * @returns Boolean indicating if signature is valid
     */
    verifyData(data: any, publicKey: string, signature: Uint8Array): boolean {
        const pubKey = PublicKey.fromString(publicKey);

        let originalData = lodash.clone(data);
        if(lodash.isString(data)) {
            data = JSON.parse(data.replace(/^[^{]+|[^}]+$/g,''))
        }

        if (data.serverSignature) {
            data.serverSignature = new Uint8Array(data.serverSignature);
        }

        let bytes = new Uint8Array(Buffer.from(lodash.isString(originalData) ? originalData : JSON.stringify(originalData)));
        let verify = pubKey.verify(bytes, signature);

        return verify;
    }
}
