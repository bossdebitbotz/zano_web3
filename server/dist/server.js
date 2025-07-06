import axios from "axios";
import Big from "big.js";
import { ZANO_ASSET_ID, ZanoError } from "./utils";
import forge from "node-forge";
class ServerWallet {
    walletUrl;
    daemonUrl;
    walletAuthToken;
    enableTransactionLogging;
    authRequired;
    transactionLogs = [];
    constructor(params) {
        this.walletUrl = params.walletUrl;
        this.daemonUrl = params.daemonUrl;
        this.enableTransactionLogging = params.enableTransactionLogging || false;
        // Check if authentication is required via environment or parameter
        this.authRequired = params.authRequired ?? (process.env.ZANO_AUTH_REQUIRED === 'true');
        // Only set auth token if authentication is required
        if (this.authRequired) {
            const token = params.walletAuthToken || process.env.ZANO_WALLET_AUTH_TOKEN;
            if (!token || token.length === 0) {
                throw new Error('ZANO_WALLET_AUTH_TOKEN is required when ZANO_AUTH_REQUIRED=true or authRequired=true');
            }
            this.walletAuthToken = token;
        }
        else {
            this.walletAuthToken = null;
        }
        if (this.enableTransactionLogging) {
            console.log(`[AUTH] Authentication ${this.authRequired ? 'ENABLED' : 'DISABLED'}`);
            if (this.authRequired) {
                console.log(`[AUTH] Using token: ${this.walletAuthToken?.substring(0, 8)}...`);
            }
        }
    }
    generateRandomString(length) {
        const bytes = forge.random.getBytesSync(Math.ceil(length / 2));
        const hexString = forge.util.bytesToHex(bytes);
        return hexString.substring(0, length);
    }
    createJWSToken(payload, secretStr) {
        const header = { alg: "HS256", typ: "JWT" };
        const encodedHeader = Buffer.from(JSON.stringify(header))
            .toString("base64")
            .replace(/=/g, "");
        const encodedPayload = Buffer.from(JSON.stringify(payload))
            .toString("base64")
            .replace(/=/g, "");
        const signature = forge.hmac.create();
        signature.start("sha256", secretStr);
        signature.update(`${encodedHeader}.${encodedPayload}`);
        const encodedSignature = forge.util
            .encode64(signature.digest().getBytes())
            .replace(/=/g, "");
        return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
    }
    generateAccessToken(httpBody) {
        // Calculate the SHA-256 hash of the HTTP body
        const md = forge.md.sha256.create();
        md.update(httpBody);
        const bodyHash = md.digest().toHex();
        // Example payload
        const payload = {
            body_hash: bodyHash,
            user: "zano_extension",
            salt: this.generateRandomString(64),
            exp: Math.floor(Date.now() / 1000) + 60, // Expires in 1 minute
        };
        const token = this.createJWSToken(payload, this.walletAuthToken || "");
        // Debug logging to see what we're sending
        if (this.enableTransactionLogging) {
            console.log(`[AUTH_DEBUG] Generated JWT token:`);
            console.log(`[AUTH_DEBUG] - Payload:`, JSON.stringify(payload, null, 2));
            console.log(`[AUTH_DEBUG] - Secret length:`, (this.walletAuthToken || "").length);
            console.log(`[AUTH_DEBUG] - Token (first 50 chars):`, token.substring(0, 50) + '...');
        }
        return token;
    }
    async fetchDaemon(method, params) {
        const startTime = Date.now();
        const logEntry = {
            timestamp: new Date().toISOString(),
            method,
            target: 'daemon',
            params: this.enableTransactionLogging ? params : '[LOGGING_DISABLED]',
        };
        const data = {
            jsonrpc: "2.0",
            id: 0,
            method: method,
            params: params,
        };
        const headers = {
            "Content-Type": "application/json",
        };
        // Daemon uses HTTP Basic Auth (--rpc-login), not JWT
        if (this.authRequired && this.walletAuthToken) {
            // SECURITY: Use environment variables for RPC credentials instead of hardcoded values
            const rpcUsername = process.env.ZANO_RPC_USERNAME || 'admin';
            const rpcPassword = process.env.ZANO_RPC_PASSWORD || 'admin';
            const credentials = Buffer.from(`${rpcUsername}:${rpcPassword}`).toString('base64');
            headers["Authorization"] = `Basic ${credentials}`;
            if (this.enableTransactionLogging) {
                console.log(`[AUTH] Using HTTP Basic Auth for daemon request with user: ${rpcUsername}`);
            }
        }
        else {
            if (this.enableTransactionLogging) {
                console.log(`[AUTH] Making unauthenticated request (auth ${this.authRequired ? 'required but token missing' : 'disabled'})`);
            }
        }
        try {
            if (this.enableTransactionLogging) {
                console.log(`[DAEMON] → ${method}:`, JSON.stringify(params, null, 2));
            }
            const response = await axios.post(this.daemonUrl, data, { headers });
            const duration = Date.now() - startTime;
            logEntry.duration = duration;
            logEntry.response = this.enableTransactionLogging ? response.data : '[LOGGING_DISABLED]';
            if (this.enableTransactionLogging) {
                console.log(`[DAEMON] ← ${method} (${duration}ms):`, JSON.stringify(response.data, null, 2));
                this.transactionLogs.push(logEntry);
                // Keep only last 100 log entries to prevent memory issues
                if (this.transactionLogs.length > 100) {
                    this.transactionLogs = this.transactionLogs.slice(-100);
                }
            }
            return response;
        }
        catch (error) {
            const duration = Date.now() - startTime;
            logEntry.duration = duration;
            logEntry.error = this.enableTransactionLogging ? error.message : '[LOGGING_DISABLED]';
            if (this.enableTransactionLogging) {
                console.error(`[DAEMON] ✗ ${method} (${duration}ms):`, error.message);
                this.transactionLogs.push(logEntry);
                if (this.transactionLogs.length > 100) {
                    this.transactionLogs = this.transactionLogs.slice(-100);
                }
            }
            throw error;
        }
    }
    async fetchWallet(method, params) {
        const startTime = Date.now();
        const logEntry = {
            timestamp: new Date().toISOString(),
            method,
            target: 'wallet',
            params: this.enableTransactionLogging ? params : '[LOGGING_DISABLED]',
        };
        const data = {
            jsonrpc: "2.0",
            id: 0,
            method: method,
            params: params,
        };
        const headers = {
            "Content-Type": "application/json",
        };
        // Wallet uses JWT authentication (Zano-Access-Token)
        if (this.authRequired && this.walletAuthToken) {
            headers["Zano-Access-Token"] = this.generateAccessToken(JSON.stringify(data));
            if (this.enableTransactionLogging) {
                console.log(`[AUTH] Using JWT authentication for wallet request`);
            }
        }
        else {
            if (this.enableTransactionLogging) {
                console.log(`[AUTH] Making unauthenticated wallet request (auth ${this.authRequired ? 'required but token missing' : 'disabled'})`);
            }
        }
        try {
            if (this.enableTransactionLogging) {
                console.log(`[WALLET] → ${method}:`, JSON.stringify(params, null, 2));
            }
            const response = await axios.post(this.walletUrl, data, { headers });
            const duration = Date.now() - startTime;
            logEntry.duration = duration;
            logEntry.response = this.enableTransactionLogging ? response.data : '[LOGGING_DISABLED]';
            if (this.enableTransactionLogging) {
                console.log(`[WALLET] ← ${method} (${duration}ms):`, JSON.stringify(response.data, null, 2));
                this.transactionLogs.push(logEntry);
                // Keep only last 100 log entries to prevent memory issues
                if (this.transactionLogs.length > 100) {
                    this.transactionLogs = this.transactionLogs.slice(-100);
                }
            }
            return response;
        }
        catch (error) {
            const duration = Date.now() - startTime;
            logEntry.duration = duration;
            logEntry.error = this.enableTransactionLogging ? error.message : '[LOGGING_DISABLED]';
            if (this.enableTransactionLogging) {
                console.error(`[WALLET] ✗ ${method} (${duration}ms):`, error.message);
                this.transactionLogs.push(logEntry);
                if (this.transactionLogs.length > 100) {
                    this.transactionLogs = this.transactionLogs.slice(-100);
                }
            }
            throw error;
        }
    }
    async updateWalletRpcUrl(rpcUrl) {
        this.walletUrl = rpcUrl;
    }
    async updateDaemonRpcUrl(rpcUrl) {
        this.daemonUrl = rpcUrl;
    }
    async getAssetsList() {
        const count = 100;
        let offset = 0;
        let allAssets = [];
        let keepFetching = true;
        while (keepFetching) {
            try {
                const response = await this.fetchDaemon("get_assets_list", {
                    count,
                    offset,
                });
                const assets = response.data.result.assets;
                if (assets.length < count) {
                    keepFetching = false;
                }
                allAssets = allAssets.concat(assets);
                offset += count;
            }
            catch (error) {
                throw new ZanoError("Failed to fetch assets list", "ASSETS_FETCH_ERROR");
            }
        }
        return allAssets;
    }
    async getAssetDetails(assetId) {
        const assets = await this.getAssetsList();
        const asset = assets.find((a) => a.asset_id === assetId);
        if (!asset) {
            throw new ZanoError(`Asset with ID ${assetId} not found`, "ASSET_NOT_FOUND");
        }
        return asset;
    }
    async getAssetInfo(assetId) {
        try {
            const response = await this.fetchDaemon("get_asset_info", {
                asset_id: assetId,
            });
            if (response.data.result) {
                return response.data.result;
            }
            else {
                throw new ZanoError(`Error fetching info for asset ID ${assetId}`, "ASSET_INFO_ERROR");
            }
        }
        catch (error) {
            console.error(error);
            throw new ZanoError("Failed to fetch asset info", "ASSET_INFO_FETCH_ERROR");
        }
    }
    async sendTransfer(assetId, address, amount) {
        let decimalPoint;
        let auditable;
        if (assetId === ZANO_ASSET_ID) {
            decimalPoint = 12;
        }
        else {
            const asset = await this.getAssetDetails(assetId);
            decimalPoint = asset.decimal_point;
        }
        try {
            const response = await this.fetchWallet("getaddress", {});
            auditable = response.data.result.address.startsWith("a");
        }
        catch (error) {
            throw new ZanoError("Failed to fetch address", "ADDRESS_FETCH_ERROR");
        }
        const bigAmount = new Big(amount)
            .times(new Big(10).pow(decimalPoint))
            .toString();
        try {
            const response = await this.fetchWallet("transfer", {
                destinations: [{ address, amount: bigAmount, asset_id: assetId }],
                fee: "10000000000",
                mixin: auditable ? 0 : 15,
            });
            if (response.data.result) {
                return response.data.result;
            }
            else if (response.data.error &&
                response.data.error.message === "WALLET_RPC_ERROR_CODE_NOT_ENOUGH_MONEY") {
                throw new ZanoError("Not enough funds", "NOT_ENOUGH_FUNDS");
            }
            else {
                throw new ZanoError("Error sending transfer", "TRANSFER_ERROR");
            }
        }
        catch (error) {
            if (error instanceof ZanoError) {
                throw error;
            }
            else {
                throw new ZanoError("Failed to send transfer", "TRANSFER_SEND_ERROR");
            }
        }
    }
    async getAliasByAddress(address) {
        try {
            const response = await this.fetchDaemon("get_alias_by_address", address);
            if (response.data.result) {
                return response.data.result;
            }
            else {
                throw new ZanoError(`Error fetching alias for address ${address}`, "ALIAS_FETCH_ERROR");
            }
        }
        catch (error) {
            throw new ZanoError("Failed to fetch alias", "ALIAS_FETCH_ERROR");
        }
    }
    async getBalances() {
        try {
            const response = await this.fetchWallet("getbalance", {});
            const balancesData = response.data.result.balances;
            const balances = balancesData.map((asset) => ({
                name: asset.asset_info.full_name,
                ticker: asset.asset_info.ticker,
                id: asset.asset_info.asset_id,
                amount: new Big(asset.unlocked)
                    .div(new Big(10).pow(asset.asset_info.decimal_point))
                    .toString(),
                awaiting_in: new Big(asset.awaiting_in).toString(),
                awaiting_out: new Big(asset.awaiting_out).toString(),
                total: new Big(asset.total).toString(),
                unlocked: new Big(asset.unlocked).toString(),
                asset_info: asset.asset_info,
            }));
            return balances.sort((a, b) => {
                if (a.id === ZANO_ASSET_ID)
                    return -1;
                if (b.id === ZANO_ASSET_ID)
                    return 1;
                return 0;
            });
        }
        catch (error) {
            throw new ZanoError("Failed to fetch balances", "BALANCES_FETCH_ERROR");
        }
    }
    async validateWallet(authData) {
        const { message, address, signature } = authData;
        const alias = authData.alias || undefined;
        const pkey = authData.pkey || undefined;
        if (!message || (!alias && !pkey) || !signature) {
            return false;
        }
        const validationParams = {
            buff: Buffer.from(message).toString("base64"),
            sig: signature,
        };
        if (alias) {
            validationParams["alias"] = alias;
        }
        else {
            validationParams["pkey"] = pkey;
        }
        const response = await this.fetchDaemon("validate_signature", validationParams);
        const valid = response?.data?.result?.status === "OK";
        if (!valid) {
            return false;
        }
        if (alias) {
            const aliasDetailsResponse = await this.fetchDaemon("get_alias_details", {
                alias: alias,
            });
            const aliasDetails = aliasDetailsResponse?.data?.result?.alias_details;
            const aliasAddress = aliasDetails?.address;
            const addressValid = !!aliasAddress && aliasAddress === address;
            if (!addressValid) {
                return false;
            }
        }
        return valid;
    }
    async getTxs(params) {
        const txs = await this.fetchWallet("get_recent_txs_and_info2", {
            count: params.count,
            exclude_mining_txs: params.exclude_mining_txs || false,
            exclude_unconfirmed: params.exclude_unconfirmed || false,
            offset: params.offset,
            order: params.order || "FROM_END_TO_BEGIN",
            update_provision_info: params.update_provision_info || true,
        });
        return txs.data.result;
    }
    async getAliasDetails(alias) {
        try {
            const response = await this.fetchDaemon("get_alias_details", {
                alias,
            });
            if (response.data.result) {
                return response.data.result;
            }
            else {
                throw new ZanoError(`Error fetching alias ${alias}`, "ALIAS_FETCH_ERROR");
            }
        }
        catch {
            throw new ZanoError("Failed to fetch alias", "ALIAS_FETCH_ERROR");
        }
    }
    // Transaction logging utility methods
    enableLogging() {
        this.enableTransactionLogging = true;
        console.log('[ZANO] Transaction logging enabled');
    }
    disableLogging() {
        this.enableTransactionLogging = false;
        console.log('[ZANO] Transaction logging disabled');
    }
    getTransactionLogs(limit) {
        if (!this.enableTransactionLogging) {
            return [];
        }
        const logs = this.transactionLogs;
        return limit ? logs.slice(-limit) : logs;
    }
    getTransactionLogsByMethod(method) {
        if (!this.enableTransactionLogging) {
            return [];
        }
        return this.transactionLogs.filter(log => log.method === method);
    }
    getTransactionLogsByTarget(target) {
        if (!this.enableTransactionLogging) {
            return [];
        }
        return this.transactionLogs.filter(log => log.target === target);
    }
    clearTransactionLogs() {
        this.transactionLogs = [];
        console.log('[ZANO] Transaction logs cleared');
    }
    // Enhanced transfer method with detailed transaction logging
    async sendTransferWithLogging(assetId, address, amount, comment) {
        if (this.enableTransactionLogging) {
            console.log(`[TRANSACTION] Starting transfer of ${amount} (asset: ${assetId}) to ${address}`);
            if (comment) {
                console.log(`[TRANSACTION] Comment: ${comment}`);
            }
        }
        try {
            const result = await this.sendTransfer(assetId, address, amount);
            if (this.enableTransactionLogging && result.tx_hash) {
                console.log(`[TRANSACTION] ✓ Transfer successful - TX Hash: ${result.tx_hash}`);
                // Get transaction details from daemon for verification
                setTimeout(async () => {
                    try {
                        await this.getTransactionDetails(result.tx_hash);
                    }
                    catch (error) {
                        console.log(`[TRANSACTION] Could not fetch transaction details yet for ${result.tx_hash}`);
                    }
                }, 2000);
            }
            return result;
        }
        catch (error) {
            if (this.enableTransactionLogging) {
                console.error(`[TRANSACTION] ✗ Transfer failed:`, error);
            }
            throw error;
        }
    }
    // Get transaction details from daemon
    async getTransactionDetails(txHash) {
        try {
            const response = await this.fetchDaemon("get_transactions", {
                txs_hashes: [txHash]
            });
            if (response.data.result && response.data.result.txs) {
                const tx = response.data.result.txs[0];
                if (this.enableTransactionLogging) {
                    console.log(`[TX_DETAILS] Transaction ${txHash}:`);
                    console.log(`  - Block Height: ${tx.block_height || 'pending'}`);
                    console.log(`  - Confirmations: ${tx.confirmations || 0}`);
                    console.log(`  - Status: ${tx.in_pool ? 'in mempool' : 'confirmed'}`);
                }
                return tx;
            }
            throw new Error('Transaction not found');
        }
        catch (error) {
            if (this.enableTransactionLogging) {
                console.log(`[TX_DETAILS] Could not get details for ${txHash}: ${error.message}`);
            }
            throw error;
        }
    }
    // Get mempool stats from daemon
    async getMempoolStats() {
        try {
            const response = await this.fetchDaemon("get_transaction_pool_stats", {});
            if (this.enableTransactionLogging && response.data.result) {
                const stats = response.data.result.pool_stats;
                console.log(`[MEMPOOL] ${stats.txs_total} transactions, size: ${stats.bytes_total} bytes`);
            }
            return response.data.result;
        }
        catch (error) {
            if (this.enableTransactionLogging) {
                console.error(`[MEMPOOL] Error getting mempool stats: ${error.message}`);
            }
            throw error;
        }
    }
}
export default ServerWallet;
//# sourceMappingURL=server.js.map