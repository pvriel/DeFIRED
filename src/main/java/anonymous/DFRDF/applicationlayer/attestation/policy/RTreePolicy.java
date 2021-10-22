package anonymous.DFRDF.applicationlayer.attestation.policy;

import org.apache.commons.lang3.ArrayUtils;
import org.jetbrains.annotations.NotNull;

import java.io.Serializable;
import java.util.*;

import static anonymous.DFRDF.applicationlayer.attestation.policy.PolicyRight.*;

/**
 * Class expressing an RTree policy expression.
 */
public class RTreePolicy implements Serializable, Cloneable {

    private PolicyRight policyRight;
    private final String[] namespaceDirectoryExpression;

    /**
     * Constructor for the {@link RTreePolicy} class.
     * @param   policyRight
     *          The access right of the policy (READ / WRITE).
     * @param   namespaceDirectories
     *          Strings expressing the directory of the namespace.
     *          E.g. "A", "B" ==> RTreePolicy expressing access to the namespace "A/B", according
     *          to the policy right.
     *          At least one String should be provided.
     */
    public RTreePolicy(@NotNull PolicyRight policyRight, @NotNull String... namespaceDirectories) {
        if (namespaceDirectories.length == 0) throw new IllegalArgumentException("Not enough namespace directories provided.");
        for (String namespaceDirectory : namespaceDirectories) {
            if (namespaceDirectory.contains("/"))
                throw new IllegalArgumentException(" The / character is not allowed for the namespace directories.");
        }

        this.policyRight = policyRight;
        namespaceDirectoryExpression = namespaceDirectories;
    }

    /**
     * Constructor for the {@link RTreePolicy} class.
     * @param   rTreePolicy
     *          The previous {@link RTreePolicy} to extend.
     * @param   policyRight
     *          The {@link PolicyRight} of the new {@link RTreePolicy} instance.
     * @param   namespaceDirectories
     *          The namespace directories to extend the provided {@link RTreePolicy} with.
     */
    public RTreePolicy(@NotNull RTreePolicy rTreePolicy, @NotNull PolicyRight policyRight, @NotNull String... namespaceDirectories) {
        this(policyRight, ArrayUtils.addAll(rTreePolicy.namespaceDirectoryExpression, namespaceDirectories));
    }

    /**
     * Getter for the {@link PolicyRight}.
     * @return  The {@link PolicyRight}.
     */
    public PolicyRight getPolicyRight() {
        return policyRight;
    }

    /**
     * Setter for the {@link PolicyRight}.
     * @param   policyRight
     *          Setter for the {@link PolicyRight}.
     */
    public void setPolicyRight(@NotNull PolicyRight policyRight) {
        this.policyRight = policyRight;
    }

    /**
     * Method to generate and return all {@link RTreePolicy} variations of this instance.
     * @return  The result as a {@link List}.
     */
    public List<RTreePolicy> generateRTreePolicyVariations() {
        List<RTreePolicy> returnValue = new ArrayList<>();
        var currentlyEvaluatedPolicy = this;

        while (true) {
            returnValue.add(currentlyEvaluatedPolicy);

            var copy = currentlyEvaluatedPolicy.clone();
            copy.setPolicyRight(copy.getPolicyRight().equals(WRITE)? READ: WRITE);
            returnValue.add(copy);

            try {
                currentlyEvaluatedPolicy = new RTreePolicy(currentlyEvaluatedPolicy.policyRight,
                        Arrays.copyOfRange(currentlyEvaluatedPolicy.namespaceDirectoryExpression, 0,
                                currentlyEvaluatedPolicy.namespaceDirectoryExpression.length - 1));
            } catch (Exception ignored) {break;}
        }

        return returnValue;
    }

    /**
     * Method to check if this {@link RTreePolicy} object covers the RTree policy of another {@link RTreePolicy} object.
     * This is the case if the following criteria are met:
     * - The {@link PolicyRight} of this {@link RTreePolicy} object is at least as expressive as the {@link PolicyRight}
     * of the other {@link RTreePolicy} object, with WRITE > READ.
     * - The namespace directory of this object is either a parent namespace directory of the provided object,
     * or is the same namespace directory as the namespace directory of the provided object.
     * @param   otherRTreePolicy
     *          The other {@link RTreePolicy} object.
     * @return  True if this {@link RTreePolicy} object covers the RTree policy of the provided {@link RTreePolicy} object;
     *  false otherwise.
     */
    public boolean coversRTreePolicy(@NotNull RTreePolicy otherRTreePolicy) {
        if (namespaceDirectoryExpression.length > otherRTreePolicy.namespaceDirectoryExpression.length) return false;

        for (int i = 0; i < namespaceDirectoryExpression.length; i ++)
            if (!namespaceDirectoryExpression[i].equals(otherRTreePolicy.namespaceDirectoryExpression[i]))
                return false;

        return otherRTreePolicy.policyRight.equals(READ) || policyRight.equals(WRITE);
    }

    @Override
    public RTreePolicy clone() {
        return new RTreePolicy(policyRight, namespaceDirectoryExpression);
    }

    @Override
    public String toString() {
        StringBuilder resultBuilder = new StringBuilder(String.format("%s://", policyRight.name()));
        for (String namespaceDirectory : namespaceDirectoryExpression)
            resultBuilder.append(String.format("%s/", namespaceDirectory));
        if (namespaceDirectoryExpression.length > 0) resultBuilder.deleteCharAt(resultBuilder.length() - 1);
        return resultBuilder.toString();
    }

    /**
     * Method to convert a String, expressing an RTree policy, to an {@link RTreePolicy} instance.
     * @param   expressedRTreePolicy
     *          The expressed RTree policy.
     * @return  An {@link RTreePolicy} instance.
     * @throws  IllegalArgumentException
     *          If the provided RTree policy does not express a valid RTree policy.
     */
    public static @NotNull RTreePolicy convertStringToRTreePolicy(@NotNull String expressedRTreePolicy) throws IllegalArgumentException {
        PolicyRight policyRight = null;
        for (PolicyRight consideredPolicyRight : values()) {
            if (expressedRTreePolicy.startsWith(consideredPolicyRight.name())) {
                policyRight = consideredPolicyRight;
                expressedRTreePolicy = expressedRTreePolicy.substring(policyRight.name().length() + "://".length());
                break;
            }
        }
        if (policyRight == null) throw new IllegalArgumentException("Given String does not start with a valid PolicyRight expression.");

        return new RTreePolicy(policyRight, expressedRTreePolicy.split("/"));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RTreePolicy that = (RTreePolicy) o;
        return policyRight == that.policyRight && Arrays.equals(namespaceDirectoryExpression, that.namespaceDirectoryExpression);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(policyRight);
        result = 31 * result + Arrays.hashCode(namespaceDirectoryExpression);
        return result;
    }
}
