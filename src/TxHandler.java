import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TxHandler {
    private UTXOPool utxoPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
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
        return hasOutputs(tx)
            && hasValidSignatures(tx)
            && hasNoMultipleClaims(tx)
            && hasPositiveValues(tx)
            && hasInputGreaterThanOutput(tx);
    }
    
    private boolean hasOutputs(Transaction tx) {
        return  // 1. Get all the transaction inputs as a stream
                tx.getInputs().stream()
                // 2. Map each input into the corresponding UTXO
                .map(this::getUTXO)
                // 3. Check if all of them are in the UTXO pool
                .allMatch(utxo -> this.utxoPool.contains(utxo));
    }

    private boolean hasValidSignatures(Transaction tx) {
        Stream<Transaction.Input> inputs = tx.getInputs().stream();

        // If there are any inputs without a signature it is certainly not a valid signature
        if (inputs.anyMatch(i -> i.signature == null))
            return false;

        // For each input:
        // 1. Get the UTXO
        // 2. Get the data to sign from the transaction
        // 3. Get the public key from the output
        // 4. Verify that the signature on the input is indeed from the owner of the public key
        for (int i = 0; i < inputs.count(); i++) {
            Transaction.Input input = tx.getInput(i);
            UTXO utxo = getUTXO(input);
            byte[] data = tx.getRawDataToSign(i);
            Transaction.Output output = this.utxoPool.getTxOutput(utxo);

            if (!Crypto.verifySignature(output.address, data, input.signature))
                return false;
        }

        // If none of the inputs failed verification it means that all is well
        return true;
    }

    private boolean hasNoMultipleClaims(Transaction tx) {
        // Get UTXOs for each input
        Stream<UTXO> UTXOs = tx.getInputs().stream()
                .map(this::getUTXO);

        // if the number of distinct (unique) UTXOs is equal to the number of UTXOs in total
        // we know that there are no duplicates
        return UTXOs.distinct().count() == UTXOs.count();
    }

    private boolean hasPositiveValues(Transaction tx) {
        // Check that each output from the transaction has a value greater or equal to zero
        return tx.getOutputs().stream()
                .allMatch(output -> output.value >= 0);
    }

    private boolean hasInputGreaterThanOutput(Transaction tx) {
        // 1. Find the corresponding output for each input
        // 2. Get the sum of all the outputs used
        double inputSum = tx.getInputs().stream()
                .map(this::getUTXO)
                .map(this.utxoPool::getTxOutput)
                .mapToDouble(output -> output.value)
                .sum();

        // 2. Get the sum of the outputs in the transaction
        double outputSum = tx.getOutputs().stream()
                .mapToDouble(output -> output.value)
                .sum();

        return inputSum >= outputSum;
    }

    /**
     * Helper function to get a UTXO from a transaction input
     */
    private UTXO getUTXO(Transaction.Input input) {
        return new UTXO(input.prevTxHash, input.outputIndex);
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        ArrayList<Transaction> acceptedTransactions = new ArrayList<>();

        while(true) {
            // Filter out the transactions that are valid transactions on top of the current unspent transaction pool
            Stream<Transaction> validTxs = Arrays.stream(possibleTxs)
                    .filter(this::isValidTx);

            // If there are no more valid transactions to process we can stop
            if (validTxs.count() == 0)
                break;

            for (Transaction tx : validTxs.collect(Collectors.toList())) {
                // If this transaction is no longer valid it means another transaction has already
                // spent the output that this transaction claims, and we have a double-spend.
                // Therefore, we don't add this transaction to the utxo pool
                if (!this.isValidTx(tx))
                    continue;

                // Otherwise, this transaction is valid and we can continue

                // First remove the unspent transaction outputs (UTXOs) claimed by this transaction
                // from the utxo pool
                tx.getInputs().stream().map(this::getUTXO).forEach(utxoPool::removeUTXO);

                // Then add the new UTXOs created from the outputs in this transaction
                for (int i = 0; i < tx.numOutputs(); i++) {
                    UTXO utxo = new UTXO(tx.getHash(), i);
                    utxoPool.addUTXO(utxo, tx.getOutput(i));
                }

                // Add this transaction to the list of accepted transactions
                acceptedTransactions.add(tx);
            }
        }

        // Return an array of all the transactions that were accepted
        return acceptedTransactions.toArray(Transaction[]::new);
    }
}
