package vrielynckpieterjan.applicationlayer.policy;

import org.jetbrains.annotations.NotNull;

import java.io.Serializable;
import java.util.Arrays;

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
        this.policyRight = policyRight;
        namespaceDirectoryExpression = namespaceDirectories;
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
     * Getter for the amount of namespace directories provided as arguments for the constructor.
     * @return  The amount of namespace directories provided as arguments for the constructor.
     */
    public int getAmountOfNamespaceDirectories() {
        return namespaceDirectoryExpression.length;
    }

    /**
     * Method to generate an {@link RTreePolicy} for the namespace's parent directory with the same {@link PolicyRight}.
     * As an example, if this object would express the RTree policy "write://A/B", a newly generated
     * {@link RTreePolicy} object will be returned, which expresses the RTree policy "write://A".
     * @return  The RTree policy for the namespace's parent directory, with the same {@link PolicyRight}.
     * @throws  IllegalStateException
     *          If the namespace of this {@link RTreePolicy} object does not have any parent directory.
     *          As an example, this is the case with "write://A".
     */
    public RTreePolicy generateRTreePolicyForNamespaceParentDirectory() throws IllegalStateException {
        if (namespaceDirectoryExpression.length <= 1)
            throw new IllegalStateException("No namespace parent directory found for this RTreePolicy object.");

        String[] namespaceDirectoriesAsArray = Arrays.copyOfRange(
                namespaceDirectoryExpression, 0, namespaceDirectoryExpression.length - 1);
        return new RTreePolicy(policyRight, namespaceDirectoriesAsArray);
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

        return otherRTreePolicy.policyRight.equals(PolicyRight.READ) || policyRight.equals(PolicyRight.WRITE);
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
}
