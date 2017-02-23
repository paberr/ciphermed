/*
 * Copyright 2013-2015 Raphael Bost
 *
 * This file is part of ciphermed.

 *  ciphermed is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 * 
 *  ciphermed is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with ciphermed.  If not, see <http://www.gnu.org/licenses/>. 2
 *
 */

#include <tree/tree.hh>
//#include <tree/util.hh>

Tree<long>* balancedBinaryTree_aux(size_t n_leaves, size_t index, queue<size_t> &v_indices)
{
    assert(n_leaves > 0);
    if (n_leaves == 1) {
        return new Leaf<long>(index);
    }
    
    Tree <long> *left, *right;
    
    size_t n_leaves_left, n_leaves_right;
    n_leaves_right = n_leaves/2;
    n_leaves_left = n_leaves - n_leaves_right;
    
    left =  balancedBinaryTree_aux(n_leaves_left, index,v_indices);
    
    size_t i = v_indices.front();
    v_indices.pop();

    right = balancedBinaryTree_aux(n_leaves_right, index+n_leaves_left,v_indices);
    
    Tree<long> *res = new Node<long>(i,left,right);
    return res;

}

Tree<long>* balancedBinaryTree(size_t n_leaves)
{
    assert(n_leaves > 0);

    if (n_leaves == 1) {
        return new Leaf<long>(0);
    }
    
    queue<size_t> v_indices;
    for (size_t i = 0; i < n_leaves-1; i++) {
        v_indices.push(i);
    }
    
    return balancedBinaryTree_aux(n_leaves,0,v_indices);
}

Tree<long>* binaryRepTree(size_t level, size_t index_offset)
{
    if (level == 0) {
        return new Leaf<long>(index_offset);
    }
    
    Tree <long> *left, *right;
    right = binaryRepTree(level-1, index_offset);
    left = binaryRepTree(level-1, index_offset + (1<<(level-1)));
    
    return new Node<long>(level-1, left, right);
}

ZZX encode_leaf(const Leaf<long> &leaf, const EncryptedArray &ea)
{
    vector<long> bits = bitSet(leaf.value(), ea.size());
    ZZX poly;
    ea.encode(poly, bits);
    
    return poly;
}

Ctxt evalNode_FHE(const Node<long> &node,const vector<Ctxt> &c_b_table, const EncryptedArray &ea)
{
//    if(tree.isLeaf())
//    {
//        const FHEPubKey &pk = c_b_table[0].getPubKey();
//        Ctxt c = Ctxt(pk);
//        ea.encrypt(c,pk,term.coefficient());
//
//        return c;
//    }
    
    size_t index = node.index();
    
    Ctxt b = c_b_table[index];
    Ctxt b_neg = ctxt_neg(b,ea);
    
    Ctxt left(b), right(b_neg);
    if (node.leftChild()->isLeaf()) {
        ZZX coeffPoly = encode_leaf(*((Leaf<long> *)node.leftChild()), ea);

        left.multByConstant(coeffPoly);
        
    }else{
        left *= evalNode_FHE(*((Node<long> *)node.leftChild()), c_b_table, ea);
    }
    
    if (node.rightChild()->isLeaf()) {
        ZZX coeffPoly = encode_leaf(*((Leaf<long> *)node.rightChild()), ea);
        
        right.multByConstant(coeffPoly);
        
    }else{
        right *= evalNode_FHE(*((Node<long> *)node.rightChild()), c_b_table, ea);
    }
    
    left += right;
    
    return left;
}