public class TxHandler {
    public static void main(String[] args) {
        System.out.println("Testing 123");
    }

    private UTXOPool utxoPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        // IMPLEMENT THIS
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        // IMPLEMENT THIS
        return checkOutputs(tx)
            && checkSignatures(tx);
    }
    
    private boolean checkOutputs(Transaction tx) {
        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            if (!this.utxoPool.contains(utxo))
                return false;
        }
        return true;
    }

    private boolean checkSignatures(Transaction tx) {
        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            Transaction.Output output = this.utxoPool.getTxOutput(utxo);

            if (!Crypto.verifySignature(output.address, input.prevTxHash, input.signature))
                return false;
        }
        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        // IMPLEMENT THIS

        return new Transaction[0];
    }

}
