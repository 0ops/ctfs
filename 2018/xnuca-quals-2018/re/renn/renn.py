import tensorflow as tf
import numpy as np
from math import isclose

def get_input():
    secret = input("what is your secret:")
    secret = secret[:32].rjust(16,'\x00')
    X = np.array([float(ord(x))/128 for x in secret])
    return X

def judge(a, b):
    for (m,n) in zip(a, b):
        if not isclose(m, n, rel_tol=1e-8):
            print("Sorry, srcret wrong! Try harder?")
            return False
    print("You got it!")
    return True

if __name__ == "__main__":
    X = get_input()
    sess = tf.Session()
    saver = tf.train.import_meta_graph('model.meta')
    saver.restore(sess, tf.train.latest_checkpoint('./'))
    graph = tf.get_default_graph()
    x = graph.get_tensor_by_name('In_string:0')
    y = graph.get_tensor_by_name("Out_judge:0")
    final = np.array([[1.40895243e-01, 9.98096014e-01, 1.13422030e-02, 6.57041353e-01,
        9.97613889e-01, 9.98909625e-01, 9.92840464e-01, 9.90108787e-01,
        1.43269835e-03, 9.89027450e-01, 7.22652880e-01, 9.63670217e-01,
        6.89424259e-01, 1.76012035e-02, 9.30893743e-01, 8.61464445e-03,
        4.35839722e-01, 8.38741174e-04, 6.38429400e-02, 9.90384032e-01,
        1.09806946e-03, 1.76375112e-03, 9.37186997e-01, 8.32329340e-01,
        9.83474966e-01, 8.79308946e-01, 6.59324698e-03, 7.85916088e-05,
        2.94269115e-05, 1.97006621e-03, 9.99416387e-01, 9.99997202e-01]])
    
    res = sess.run(y, feed_dict={x:[X]})
    
    judge(res[0], final[0])
    for i in range(len(res.tolist()[0])):
        print(i,res.tolist()[0][i])
