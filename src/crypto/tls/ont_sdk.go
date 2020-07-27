package tls

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	sdk "github.com/ontio/ontology-go-sdk"
)

func GetPubKeyByDid(did string, ontSdk *sdk.OntologySdk) (string, error) {
	if ontSdk.Native == nil || ontSdk.Native.OntId == nil {
		return "", fmt.Errorf("ontsdk is nil")
	}
	pubKey, err := ontSdk.Native.OntId.GetPublicKeysJson(did)
	if err != nil {
		return "", err
	}
	var pks []DidPubkey
	err = json.Unmarshal(pubKey, &pks)
	if err != nil {
		return "", err
	}
	if len(pks) == 0 {
		return "", fmt.Errorf("no public key found")
	}

	return pks[0].PublicKeyHex, nil
}

func VerifyDid(did,url string,didSignData []byte) (bool, error) {
	ontSdk := GetOntSdk(url)
	pub ,err := GetPubKeyByDid(did,ontSdk)
	if err != nil {
		return false,fmt.Errorf("GetPubKey ByDid did:%s, err:%s",did,err)
	}
	pubKey, err := hex.DecodeString(pub)
	if err != nil {
		return false, fmt.Errorf("hex DecodeString err:%s", err)
	}
	pk, err := keypair.DeserializePublicKey(pubKey)
	if err != nil {
		return false, fmt.Errorf("Deserialize PubKey err:%s", err)
	}
	didData, err := hex.DecodeString(did)
	if err != nil {
		return false, fmt.Errorf("hex DecodeString err:%s", err)
	}
	if !signature.Verify(pk, didData, didSignData) {
		return false, fmt.Errorf("verify sign err")
	}
	return true,nil
}

func GetOntSdk(rpcUrl string) *sdk.OntologySdk {
	ontSdk := sdk.NewOntologySdk()
	return 	ontSdk.NewRpcClient().SetAddress(rpcUrl)
}

func CreateCredential(contexts,types []string,credentialSubject interface{}, issuerId interface{},
expirationDateTimestamp int64, challenge string, domain interface{}, signer *sdk.Account,ontSdk *sdk.OntologySdk) ([]byte,error){
	credential,err := ontSdk.Credential.CreateCredential(contexts,types,credentialSubject,issuerId.ID,expirationDateTimestamp,
		challenge,domain,signer)
	if err != nil {
		return nil,err
	}
	data, err := json.Marshal(credential)
	if err != nil {
		return nil,err
	}
	return data,nil
}

func VerifyCredential(data []byte,did,rpcUrl string)(bool,error) {
	ontSdk := GetOntSdk(rpcUrl)
	credential := &sdk.VerifiableCredential{}
	err := json.Unmarshal(data,credentail)
	if err != nil {
		return false,err
	}
	err = ontSdk.Credential.VerifyCredibleOntId([]string{did}, credential)
	if err != nil {
		return false, err
	}
	err = ontSdk.Credential.VerifyIssuanceDate(credential)
	if err != nil {
		return false, err
	}
	err = ontSdk.Credential.VerifyExpirationDate(credential)
	if err != nil {
		return false, err
	}
	err = ontSdk.Credential.VerifyIssuerSignature(credential)
	if err != nil {
		return false, err
	}
	err = ontSdk.Credential.VerifyStatus(credential)
	if err != nil {
		return false, err
	}
	return true,nil
}