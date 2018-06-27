/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl;

import java.io.Serializable;

import org.digidoc4j.Signature;

public interface SignatureFinalizer extends Serializable {

  /**
   * Adds signature value and constructs the signature object
   *
   * @param signatureValue signature value bytes
   * @return signature object
   */
  Signature finalizeSignature(byte[] signatureValue);

}
