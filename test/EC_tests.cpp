/*
 * EC_tests.cpp
 *
 *  Created on: 18.07.2014
 *      Author: timm
 */

#include "gtest/gtest.h"

//#include <cryptopp/asn.h>
//#include <cryptopp/cryptlib.h>
//#include <cryptopp/ec2n.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/ecp.h>
#include <cryptopp/filters.h>
#include <cryptopp/integer.h>
#include <cryptopp/mqueue.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>

#include <cstdio>

#include <iostream>
#include <string>
#include <vector>


TEST(PlayingWithECs, EC_DSA) {
//  CryptoPP::ECDSA<CryptoPP::EC2N, CryptoPP::SHA1>::Signer signer;
//  CryptoPP::ECDSA<CryptoPP::EC2N, CryptoPP::SHA1>::Verifier verifier;

  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PrivateKey privateKey;

  privateKey.Initialize( prng, CryptoPP::ASN1::secp160r1() );
  const bool isValidKey = privateKey.Validate( prng, 3 );
  if (not isValidKey)
    FAIL();

  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::Signer signer(privateKey);

  const bool isValidSignerKey = signer.AccessKey().Validate( prng, 3 );
  if (not isValidSignerKey)
    FAIL();

  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PublicKey publicKey;

  privateKey.MakePublicKey( publicKey );

  const bool isValidPubKey = publicKey.Validate( prng, 3 );
  if (not isValidPubKey)
    FAIL();

  CryptoPP::MessageQueue queue;

  publicKey.Save(queue);

  std::vector<byte> out(214, 0);

  std::cerr << "Num bytes: " << queue.MaxRetrievable() << std::endl;

  queue.Get(&*(out.begin()), 214);

  if (queue.MaxRetrievable() > 0)
    FAIL();

  for (byte b: out) {
    fprintf(stderr, "%02hhx.", static_cast<unsigned int>(b));
//    std::cerr << std::hex << static_cast<unsigned short>(reinterpret_cast<char &>(b));
  }

  CryptoPP::MessageQueue queue2;
  std::cerr << std::endl << "Num bytes (empty queue): " << queue2.MaxRetrievable() << std::endl;

  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PublicKey::Element publicPoint = publicKey.GetPublicElement();

  std::cerr << "Min x encode length: " << publicPoint.x.MinEncodedSize() << std::endl;
  std::cerr << "Min y encode length: " << publicPoint.y.MinEncodedSize() << std::endl;

  std::vector<byte> pointEncode(40, 0);
  publicPoint.x.Encode(&*(pointEncode.begin()), 20);
  publicPoint.y.Encode(&(*(pointEncode.begin() + 20)), 20);

  for (byte b: pointEncode)
    fprintf(stderr, "%02hhx.", static_cast<unsigned int>(b));

  CryptoPP::Integer x(&*(pointEncode.begin()), 20);
  CryptoPP::Integer y(&(*(pointEncode.begin() + 20)), 20);

  CryptoPP::ECPPoint newPoint(x, y);

  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PublicKey newPublicKey;
  newPublicKey.Initialize(CryptoPP::ASN1::secp160r1(), newPoint);

  std::string message = "Yoda said, Do or do not. There is no try.";
  std::string signature;

  CryptoPP::StringSource s( message, true /*pump all*/,
      new CryptoPP::SignerFilter( prng,
          CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA1>::Signer( privateKey ),
          new CryptoPP::StringSink( signature )
      ) // SignerFilter
  ); // StringSource

  // Result of the verification process
  bool verified = false;

  CryptoPP::StringSource ss( signature + message, true /*pump all*/,
      new CryptoPP::SignatureVerificationFilter(
          CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA1>::Verifier(newPublicKey),
          new CryptoPP::ArraySink( (byte*)&verified, sizeof(verified) )
      ) // SignatureVerificationFilter
  );

  // Verification failure?
  ASSERT_TRUE(verified);

  std::string signatureFalse(signature);
  signatureFalse[0] = 'a';

  CryptoPP::StringSource ssF( signatureFalse + message, true /*pump all*/,
      new CryptoPP::SignatureVerificationFilter(
          CryptoPP::ECDSA<CryptoPP::ECP,CryptoPP::SHA1>::Verifier(newPublicKey),
          new CryptoPP::ArraySink( (byte*)&verified, sizeof(verified) )
      ) // SignatureVerificationFilter
  );

  // Verification failure?
  ASSERT_FALSE(verified);
  // 0��0��*�H�=0��0 *�H�=

  // 30.81.d3.30.81.a4.06.07.2a.86.48.ce.3d.02.01.30.81.98.02.01.01.30.20.06.07.2a.86.48.ce.3d.01.01.02.15.00.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.7f.ff.ff.ff.30.2c.04.14.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.7f.ff.ff.fc.04.14.1c.97.be.fc.54.bd.7a.8b.65.ac.f8.9f.81.d4.d4.ad.c5.65.fa.45.04.29.04.4a.96.b5.68.8e.f5.73.28.46.64.69.89.68.c3.8b.b9.13.cb.fc.82.23.a6.28.55.31.68.94.7d.59.dc.c9.12.04.23.51.37.7a.c5.fb.32.02.15.01.00.00.00.00.00.00.00.00.00.01.f4.c8.f9.27.ae.d3.ca.75.22.57.02.01.01.03.2a.00.04.16.f5.33.1a.b8.e1.95.a3.33.22.e2.53.ca.19.3c.f1.b0.9e.88.6c.e7.86.ca.08.44.eb.92.62.29.4f.0d.2d.82.2e.ea.f2.b5.1d.61.20.
  // 30.81.d3.30.81.a4.06.07.2a.86.48.ce.3d.02.01.30.81.98.02.01.01.30.20.06.07.2a.86.48.ce.3d.01.01.02.15.00.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.7f.ff.ff.ff.30.2c.04.14.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.7f.ff.ff.fc.04.14.1c.97.be.fc.54.bd.7a.8b.65.ac.f8.9f.81.d4.d4.ad.c5.65.fa.45.04.29.04.4a.96.b5.68.8e.f5.73.28.46.64.69.89.68.c3.8b.b9.13.cb.fc.82.23.a6.28.55.31.68.94.7d.59.dc.c9.12.04.23.51.37.7a.c5.fb.32.02.15.01.00.00.00.00.00.00.00.00.00.01.f4.c8.f9.27.ae.d3.ca.75.22.57.02.01.01.03.2a.00.04.1b.a7.a6.86.3e.46.39.59.53.89.93.83.df.29.bb.1c.73.6f.2a.bb.6e.44.5a.cd.72.03.2c.8d.6c.58.63.57.b6.eb.65.9e.12.84.ff.c8.
  // 30.81.d3.30.81.a4.06.07.2a.86.48.ce.3d.02.01.30.81.98.02.01.01.30.20.06.07.2a.86.48.ce.3d.01.01.02.15.00.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.7f.ff.ff.ff.30.2c.04.14.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.7f.ff.ff.fc.04.14.1c.97.be.fc.54.bd.7a.8b.65.ac.f8.9f.81.d4.d4.ad.c5.65.fa.45.04.29.04.4a.96.b5.68.8e.f5.73.28.46.64.69.89.68.c3.8b.b9.13.cb.fc.82.23.a6.28.55.31.68.94.7d.59.dc.c9.12.04.23.51.37.7a.c5.fb.32.02.15.01.00.00.00.00.00.00.00.00.00.01.f4.c8.f9.27.ae.d3.ca.75.22.57.02.01.01.03.2a.00.04.9a.3b.28.10.78.b6.a6.7c.18.1d.62.c9.2c.8f.35.10.c2.6e.5a.74.7c.7d.9c.b2.56.a1.c6.6f.67.01.bf.49.7d.3b.71.4c.09.34.6c.da.
  // 30.81.d3.30.81.a4.06.07.2a.86.48.ce.3d.02.01.30.81.98.02.01.01.30.20.06.07.2a.86.48.ce.3d.01.01.02.15.00.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.7f.ff.ff.ff.30.2c.04.14.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.7f.ff.ff.fc.04.14.1c.97.be.fc.54.bd.7a.8b.65.ac.f8.9f.81.d4.d4.ad.c5.65.fa.45.04.29.04.4a.96.b5.68.8e.f5.73.28.46.64.69.89.68.c3.8b.b9.13.cb.fc.82.23.a6.28.55.31.68.94.7d.59.dc.c9.12.04.23.51.37.7a.c5.fb.32.02.15.01.00.00.00.00.00.00.00.00.00.01.f4.c8.f9.27.ae.d3.ca.75.22.57.02.01.01.03.2a.00.04.74.43.00.4c.66.5c.8e.52.f6.43.11.3c.06.10.5f.40.7f.9b.1e.36.ec.ac.66.94.b0.fc.92.99.b7.da.aa.9f.d2.46.66.eb.cd.76.58.e7.
}


