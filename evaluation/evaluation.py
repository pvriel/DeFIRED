import matplotlib.pyplot as plt
import numpy as np

# Proof objects verification
proof_object_verification_x = [i for i in range(1, 31)]
proof_object_verification_y = [38, 32, 34, 32, 33, 35, 40, 39, 41, 46, 47, 53, 52, 47, 54, 53, 54, 58, 53, 49, 56, 62,
                               60, 66, 67, 72, 76, 65, 74, 80]
trend = np.polyfit(proof_object_verification_x, proof_object_verification_y, 1)
trend_function = np.poly1d(trend)
plt.plot(proof_object_verification_x, proof_object_verification_y)
plt.plot(proof_object_verification_x, trend_function(proof_object_verification_x), "r--")
plt.xlabel("Amount of attestations")
plt.ylabel("Time (milliseconds)")
plt.show()

# Proof objects construction
proof_object_construction_x = proof_object_verification_x
proof_object_construction_same_policy_y = [137, 250, 417, 690, 993, 1290, 1614, 1890,
                                           2194, 2528, 2803, 3161, 3434, 3746, 4025,
                                           4389, 4633, 4975, 5196, 5502, 5761, 6043,
                                           6344, 6629, 7161, 7400, 7646, 8241, 8500, 8651]
trend = np.polyfit(proof_object_construction_x, proof_object_construction_same_policy_y, 1)
trend_function = np.poly1d(trend)
plt.plot(proof_object_construction_x, proof_object_construction_same_policy_y)
plt.plot(proof_object_construction_x, trend_function(proof_object_construction_x), "r--")
plt.xlabel("Amount of attestations")
plt.ylabel("Time (milliseconds)")
plt.show()


decrypting_aes_key_information_segment_nested_policies_x = [i for i in range(0, 30)]
decrypting_aes_key_information_segment_nested_policies_y = [104.3, 102.9, 156.1, 179.2, 272.3, 313.6, 333.2,
                                                            303.8, 448.7, 470.4, 522.2, 507.5, 483, 648.2,
                                                            716.1, 734.7, 623, 650, 645, 637, 600.5, 773.5,
                                                            700.6, 750, 806.4, 871.5, 872.2, 772.1, 832.5,
                                                            1001.7]
trend = np.polyfit(decrypting_aes_key_information_segment_nested_policies_x, decrypting_aes_key_information_segment_nested_policies_y, 1)
trend_function = np.poly1d(trend)
plt.plot(decrypting_aes_key_information_segment_nested_policies_x, decrypting_aes_key_information_segment_nested_policies_y)
plt.plot(decrypting_aes_key_information_segment_nested_policies_x, trend_function(decrypting_aes_key_information_segment_nested_policies_x), "r--")
plt.xlabel("Length of policy")
plt.ylabel("Time (milliseconds)")
plt.show()