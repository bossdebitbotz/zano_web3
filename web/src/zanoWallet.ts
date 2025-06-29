import { v4 as uuidv4 } from 'uuid';
import { Wallet, Asset } from './types';

export interface ZanoWalletParams {
    authPath: string;
    useLocalStorage?: boolean; // default: true
    aliasRequired?: boolean; 
    customLocalStorageKey?: string;
    customNonce?: string;
    customServerPath?: string;
    disableServerRequest?: boolean;

    onConnectStart?: (...params: any) => any;
    onConnectEnd?: (...params: any) => any;
    onConnectError?: (...params: any) => any;

    beforeConnect?: (...params: any) => any;
    onLocalConnectEnd?: (...params: any) => any;
}

type GlobalWindow = Window & typeof globalThis;

interface ZanoWindowParams {
    request: (str: string, params?: any, timeoutMs?: number | null) => Promise<any>;
    getAlias?: () => Promise<string | null>;
    getAddress?: () => Promise<string | null>;
    getBalance?: () => Promise<string | null>;
    getAssets?: () => Promise<Asset[] | null>;
}

type ZanoWindow = Omit<GlobalWindow, 'Infinity'> & {
    zano: ZanoWindowParams,
    zanoWallet: ZanoWindowParams
}

interface WalletCredentials {
    nonce: string;
    signature: string;
    publicKey: string;
    address: string;
}

class ZanoWallet {

    private DEFAULT_LOCAL_STORAGE_KEY = "wallet";
    private localStorageKey: string;

    private params: ZanoWalletParams;
    private zanoWallet: ZanoWindowParams;
    
    constructor(params: ZanoWalletParams) {

        if (typeof window === 'undefined') {
            throw new Error('ZanoWallet can only be used in the browser');
        }

        const globalWindow = (window as unknown) as ZanoWindow;
        const walletApi = globalWindow.zano || globalWindow.zanoWallet;

        if (!walletApi) {
            console.error('ZanoWallet requires the ZanoWallet extension to be installed');
        }

        this.params = params;
        this.zanoWallet = walletApi;
        this.localStorageKey = params.customLocalStorageKey || this.DEFAULT_LOCAL_STORAGE_KEY;
    }
    

    private handleError({ message } : { message: string }) {
        if (this.params.onConnectError) {
            this.params.onConnectError(message);
        } else {
            console.error(message);
        }
    }

    getSavedWalletCredentials() {
        const savedWallet = localStorage.getItem(this.localStorageKey);
        if (!savedWallet) return undefined;
        try {
            return JSON.parse(savedWallet) as WalletCredentials;
        } catch {
            return undefined;
        }
    }

    setWalletCredentials(credentials: WalletCredentials | undefined) {
        if (credentials) {
            localStorage.setItem(this.localStorageKey, JSON.stringify(credentials));
        } else {
            localStorage.removeItem(this.localStorageKey);
        }
    }

    cleanWalletCredentials() {
        this.setWalletCredentials(undefined);
    }

    async connect() {

        if (this.params.beforeConnect) {
            await this.params.beforeConnect();
        }

        if (this.params.onConnectStart) {
            this.params.onConnectStart();
        }

        const walletData = (await this.zanoWallet.request('GET_WALLET_DATA')).data;


        if (!walletData?.address) {
            return this.handleError({ message: 'Companion is offline' });
        }

        if (!walletData?.alias && this.params.aliasRequired) {
            return this.handleError({ message: 'Alias not found' });
        }

        let nonce = "";
        let signature = "";
        let publicKey = "";


        const existingWallet = this.params.useLocalStorage ? this.getSavedWalletCredentials() : undefined;

        const existingWalletValid = existingWallet && existingWallet.address === walletData.address;

        console.log('existingWalletValid', existingWalletValid);
        console.log('existingWallet', existingWallet);
        console.log('walletData', walletData);
        
        if (existingWalletValid) {
            nonce = existingWallet.nonce;
            signature = existingWallet.signature;
            publicKey = existingWallet.publicKey;
        } else {
            const generatedNonce = this.params.customNonce || uuidv4();

            const signResult = await this.zanoWallet.request(
                'REQUEST_MESSAGE_SIGN', 
                {
                    message: generatedNonce
                }, 
                null
            );

            if (!signResult?.data?.result) {
                return this.handleError({ message: 'Failed to sign message' });
            }      

            nonce = generatedNonce;
            signature = signResult.data.result.sig;
            publicKey = signResult.data.result.pkey;
        }

        
        const serverData = {
            alias: walletData.alias,
            address: walletData.address,
            signature,
            pkey: publicKey,
            message: nonce,
            isSavedData: existingWalletValid
        }

        if (this.params.onLocalConnectEnd) {
            this.params.onLocalConnectEnd(serverData);
        }

        if (!this.params.disableServerRequest) {
            const result = await fetch( this.params.customServerPath || "/api/auth", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(
                    {
                        data: serverData
                    }
                )
            })
            .then(res => res.json())
            .catch((e) => ({
                success: false,
                error: e.message
            }));  

            if (!result?.success || !result?.data) {
                return this.handleError({ message: result.error });
            }

            if (!existingWalletValid && this.params.useLocalStorage) {
                this.setWalletCredentials({
                    publicKey,
                    signature,
                    nonce,
                    address: walletData.address
                });
            }

            if (this.params.onConnectEnd) {
                this.params.onConnectEnd({
                    ...serverData,
                    token: result.data.token
                });
            }
        }

        return true;
    }
    
    async getWallet(): Promise<Wallet | null> {
        if (!this.zanoWallet) return null;
        // Try GET_WALLET_DATA first
        if (this.zanoWallet.request) {
            try {
                const walletData = await this.zanoWallet.request('GET_WALLET_DATA');
                if (walletData?.data) {
                    const data = walletData.data;
                    // If alias is missing, try to get it directly
                    if (!data.alias && this.zanoWallet.getAlias) {
                        try {
                            const alias = await this.zanoWallet.getAlias();
                            if (alias) {
                                data.alias = alias;
                            }
                        } catch (e) {
                            console.error('Error calling getAlias:', e);
                        }
                    }
                    return data as Wallet;
                }
            } catch (e) {
                console.error('Error getting wallet data via request:', e);
            }
        }

        // Fallback to legacy methods
        try {
            let address;
            let balance = '0';
            let assets: Asset[] = [];
            let alias = '';
            
            if (this.zanoWallet.getAddress) {
                address = await this.zanoWallet.getAddress();
            }

            if (!address) {
                return null;
            }

            if (this.zanoWallet.getBalance) {
                balance = (await this.zanoWallet.getBalance()) || '0';
            }
            if (this.zanoWallet.getAssets) {
                assets = (await this.zanoWallet.getAssets()) || [];
            }
            if (this.zanoWallet.getAlias) {
                alias = (await this.zanoWallet.getAlias()) || '';
            }

            return {
                address,
                balance,
                assets,
                alias,
            } as Wallet;

        } catch (err) {
            console.error('Error accessing wallet with fallback methods:', err);
            return null;
        }
    }

    async getAddressByAlias(alias: string) {
        return ((await this.zanoWallet.request('GET_ALIAS_DETAILS', { alias })) || undefined) as string | undefined;
    }

    async createAlias(alias: string) {
        return ((await this.zanoWallet.request('CREATE_ALIAS', { alias })) || undefined).data;
    }
}

export default ZanoWallet;