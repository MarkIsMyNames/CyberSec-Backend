declare module "solc" {
  interface Solc {
    (input: string): string;
  }
  const solc: Solc;
  export default solc;
}
