__author__ = "polaris"

from tensorflow.python import pywrap_tensorflow
import numpy as np

reader = pywrap_tensorflow.NewCheckpointReader("model")
var_to_shape_map = reader.get_variable_to_shape_map()
#for key in var_to_shape_map:
#    print("tensor_name: ", key)
#    print(reader.get_tensor(key))

def re_sigmoid(a):
    return -np.log((1/a)-1)

from tensorflow.python.framework import tensor_util
import tensorflow as tf
sess = tf.Session()
saver = tf.train.import_meta_graph('model.meta')
saver.restore(sess, tf.train.latest_checkpoint('./'))
graph = tf.get_default_graph()
for n in tf.get_default_graph().as_graph_def().node:
    if n.name=="PRECISEFINAL":
        final = tensor_util.MakeNdarray(n.attr['value'].tensor)

print("=========================================================")
v = np.array(reader.get_tensor("Variable"),dtype=np.float64)
v1 = np.array(reader.get_tensor("Variable_1"),dtype=np.float64)
v2 = np.array(reader.get_tensor("Variable_2"),dtype=np.float64)
v3 = np.array(reader.get_tensor("Variable_3"),dtype=np.float64)
v4 = np.array(reader.get_tensor("Variable_4"),dtype=np.float64)
v5 = np.array(reader.get_tensor("Variable_5"),dtype=np.float64)


"""

a = re_sigmoid(final[0])
a = a-v5
#print(a)
a = np.mat(a)*np.mat(v2).I
#print(a)
#print(a*np.mat(v2))
a = np.arctanh(a)
#print(a)
#print(v4)
a = a-v4
#print(a)
a = np.mat(a)*np.mat(v1).I
print(a)
a = re_sigmoid(a)
print(a)
a = a-v3
a = np.mat(a)*np.mat(v).I
print(a*128)
"""



res = final
b8 = re_sigmoid(res)
b7 = b8-v5
b6 = np.mat(b7)*np.mat(v2).I
b5 = np.arctanh(b6)
b4 = b5-v4
b3 = np.mat(b4)*np.mat(v1).I
b2 = re_sigmoid(b3)
b1 = b2-v3
b0 = np.mat(b1)*np.mat(v).I


print("".join([chr(int(round(d*128))) for d in b0.tolist()[0]]))
