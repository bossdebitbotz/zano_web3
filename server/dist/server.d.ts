import { AuthData, BalanceInfo, TxInfo, AliasDetails } from "./types";
import { APIAsset } from "./types";
export interface ConstructorParams {
    walletUrl: string;
    daemonUrl: string;
    walletAuthToken?: string;
    enableTransactionLogging?: boolean;
    authRequired?: boolean;
}
interface GetTxsParams {
    count: number;
    offset: number;
    exclude_mining_txs?: boolean;
    exclude_unconfirmed?: boolean;
    order?: string;
    update_provision_info?: boolean;
}
export interface TransactionLogEntry {
    timestamp: string;
    method: string;
    target: 'daemon' | 'wallet';
    params: any;
    response?: any;
    error?: any;
    duration?: number;
}
declare class ServerWallet {
    private walletUrl;
    private daemonUrl;
    private walletAuthToken;
    private enableTransactionLogging;
    private authRequired;
    private transactionLogs;
    constructor(params: ConstructorParams);
    private generateRandomString;
    private createJWSToken;
    private generateAccessToken;
    fetchDaemon(method: string, params: any): Promise<import("axios").AxiosResponse<any, any>>;
    fetchWallet(method: string, params: any): Promise<import("axios").AxiosResponse<any, any>>;
    updateWalletRpcUrl(rpcUrl: string): Promise<void>;
    updateDaemonRpcUrl(rpcUrl: string): Promise<void>;
    getAssetsList(): Promise<APIAsset[]>;
    getAssetDetails(assetId: string): Promise<APIAsset>;
    getAssetInfo(assetId: string): Promise<any>;
    sendTransfer(assetId: string, address: string, amount: string): Promise<any>;
    getAliasByAddress(address: string): Promise<any>;
    getBalances(): Promise<BalanceInfo[]>;
    validateWallet(authData: AuthData): Promise<boolean>;
    getTxs(params: GetTxsParams): Promise<TxInfo>;
    getAliasDetails(alias: string): Promise<AliasDetails>;
    enableLogging(): void;
    disableLogging(): void;
    getTransactionLogs(limit?: number): TransactionLogEntry[];
    getTransactionLogsByMethod(method: string): TransactionLogEntry[];
    getTransactionLogsByTarget(target: 'daemon' | 'wallet'): TransactionLogEntry[];
    clearTransactionLogs(): void;
    sendTransferWithLogging(assetId: string, address: string, amount: string, comment?: string): Promise<any>;
    getTransactionDetails(txHash: string): Promise<any>;
    getMempoolStats(): Promise<any>;
}
export default ServerWallet;
