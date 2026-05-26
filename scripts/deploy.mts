import { ethers } from "ethers";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import solc from "solc";

const __dirname = dirname(fileURLToPath(import.meta.url));

const CREDS_FILE = "/etc/securemsg/vault-credentials";

interface BlockchainSecrets {
  RPC_URL: string;
  WALLET_PRIVATE_KEY: string;
}

interface SolcOutput {
  errors?: { severity: string; message: string }[];
  contracts: { [file: string]: { [contract: string]: { abi: object[]; evm: { bytecode: { object: string } } } } };
}

function vaultCredentials(): { addr: string; roleId: string; secretId: string } {
  const fromEnv = { addr: process.env.VAULT_ADDR, roleId: process.env.VAULT_ROLE_ID, secretId: process.env.VAULT_SECRET_ID };
  if (fromEnv.addr && fromEnv.roleId && fromEnv.secretId) {
    return fromEnv as { addr: string; roleId: string; secretId: string };
  }
  const entries = Object.fromEntries(
    readFileSync(CREDS_FILE, "utf8").split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"))
      .map((l) => l.split("=", 2) as [string, string])
  );
  const { VAULT_ADDR: addr, VAULT_ROLE_ID: roleId, VAULT_SECRET_ID: secretId } = entries;
  if (!addr || !roleId || !secretId) {
    throw new Error(`Set VAULT_ADDR/VAULT_ROLE_ID/VAULT_SECRET_ID in env or ${CREDS_FILE}`);
  }
  return { addr, roleId, secretId };
}

async function readVaultSecret(path: string): Promise<BlockchainSecrets> {
  const { addr, roleId, secretId } = vaultCredentials();

  const loginRes = await fetch(`${addr}/v1/auth/approle/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role_id: roleId, secret_id: secretId }),
  });
  if (!loginRes.ok) throw new Error(`Vault login failed: ${loginRes.status} ${loginRes.statusText}`);
  const { auth } = (await loginRes.json()) as { auth: { client_token: string } };

  const secretRes = await fetch(`${addr}/v1/secret/data/${path}`, {
    headers: { "X-Vault-Token": auth.client_token },
  });
  if (!secretRes.ok) throw new Error(`Vault read failed: ${secretRes.status} ${secretRes.statusText}`);
  const { data } = (await secretRes.json()) as { data: { data: BlockchainSecrets } };
  return data.data;
}

function compile(): { abi: object[]; bytecode: string } {
  const source = readFileSync(resolve(__dirname, "../AuditLog.sol"), "utf8");
  const output = JSON.parse((solc as unknown as { compile: (i: string) => string }).compile(JSON.stringify({
    language: "Solidity",
    sources: { "AuditLog.sol": { content: source } },
    settings: { outputSelection: { "*": { "*": ["abi", "evm.bytecode"] } } },
  }))) as SolcOutput;

  const errors = (output.errors ?? []).filter((e) => e.severity === "error");
  if (errors.length > 0) throw new Error("Compilation failed:\n" + errors.map((e) => e.message).join("\n"));

  const contract = output.contracts["AuditLog.sol"]["AuditLog"];
  return { abi: contract.abi, bytecode: "0x" + contract.evm.bytecode.object };
}

async function main(): Promise<void> {
  const { RPC_URL, WALLET_PRIVATE_KEY } = await readVaultSecret("securemsg/blockchain");
  const { abi, bytecode } = compile();
  const signer = new ethers.Wallet(WALLET_PRIVATE_KEY, new ethers.JsonRpcProvider(RPC_URL));
  const contract = await new ethers.ContractFactory(abi, bytecode, signer).deploy();
  await contract.waitForDeployment();
  console.log("AuditLog deployed to:", await contract.getAddress());
}

main().catch((err: unknown) => { console.error(err); process.exit(1); });
