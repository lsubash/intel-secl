package ocicrypt_keyprovider

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/containers/ocicrypt/keywrap/keyprovider"
	cLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	ocicrypt_keyprovider "github.com/intel-secl/intel-secl/v5/pkg/model/ocicrypt"
	"github.com/intel-secl/intel-secl/v5/pkg/wpm/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wpm/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wpm/util"
	"github.com/pkg/errors"
	"io"
	"os"
	"strings"
)

var log = cLog.GetDefaultLogger()

// AES_GCM Helper Functions
func aesEncrypt(kek []byte, symKey []byte) ([]byte, error) {
	log.Trace("pkg/wpm/ocicrypt-keyprovider/keyprovider.go:aesEncrypt() Entering")
	defer log.Trace("pkg/wpm/ocicrypt-keyprovider/keyprovider.go:aesEncrypt() Leaving")

	if len(kek) != 32 {
		return nil, errors.New("Expected 256 bit key")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, symKey, nil)
	aesp := ocicrypt_keyprovider.AesPacket{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}

	return json.Marshal(aesp)
}

func GetKey(stdInput *os.File) error {
	log.Trace("pkg/wpm/ocicrypt-keyprovider/keyprovider.go:GetKey() Entering")
	defer log.Trace("pkg/wpm/ocicrypt-keyprovider/keyprovider.go:GetKey() Leaving")

	var input keyprovider.KeyProviderKeyWrapProtocolInput

	err := json.NewDecoder(stdInput).Decode(&input)
	if err != nil {
		return errors.Wrap(err, "Error while decoding KeyProviderKeyWrapProtocolInput")
	}
	cfg, err := config.LoadConfiguration()
	if err != nil {
		return errors.Wrap(err, "Error loading WPM configuration")
	}
	var symKey, wrappedKey []byte
	var keyUrlString string

	if input.Operation == keyprovider.OpKeyWrap {
		ecParames := input.KeyWrapParams.Ec.Parameters
		if _, ok := ecParames[cfg.OcicryptKeyProviderName]; !ok {
			return errors.New("Unsupported protocol")
		}

		//For default encryption request  skopeo copy --encryption-key provider:isecl  oci:ruby oci:ruby:enc ep["isecl"] = [[]]
		//For encryption request wjth asset tags  skopeo copy --encryption-key provider:isecl:asset-tag:country:<country-value>  oci:ruby oci:ruby:enc ep["isecl"] = [["assetTag:key:value"]]
		//For encryption request with existing key id skopeo copy --encryption-key provider:isecl:key-id:<key-id-value>  oci:ruby oci:ruby:enc ep["isecl"] = [["keyId:id"]]
		params := string(ecParames[cfg.OcicryptKeyProviderName][0])
		idx := strings.Index(params, ":")
		if idx > 0 {

			encCriteria := params[:idx]
			values := params[idx+1:]

			log.Debugf("encCriteria %s", encCriteria)

			switch encCriteria {
			case constants.OcicryptKeyProviderAssetTag:
				wrappedKey, keyUrlString, err = util.FetchKey("", values)
				if err != nil {
					return errors.Wrap(err, "Error while creating key")
				}
				symKey, err = util.UnwrapKey(wrappedKey, constants.EnvelopePrivatekeyLocation)
				if err != nil {
					return errors.Wrap(err, "Error while unwrapping the key")
				}
			case constants.OcicryptKeyProviderKeyId:
				keyId := values
				wrappedKey, keyUrlString, err = util.FetchKey(keyId, "")
				if err != nil {
					return errors.Wrap(err, "Error while fetching key")
				}
				symKey, err = util.UnwrapKey(wrappedKey, constants.EnvelopePrivatekeyLocation)
				if err != nil {
					return errors.Wrap(err, "Error while unwrapping the key")
				}
			default:
				log.Info("Encryption criteria not provided, falling back to default criteria with creating new key for every layer")
				wrappedKey, keyUrlString, err = util.FetchKey("", "")
				if err != nil {
					return errors.Wrap(err, "Error while creating key")
				}
				symKey, err = util.UnwrapKey(wrappedKey, constants.EnvelopePrivatekeyLocation)
				if err != nil {
					return errors.Wrap(err, "Error while unwrapping the key")
				}
			}
		} else {
			log.Info("Encryption criteria not provided, falling back to default criteria with creating new key for every layer")
			wrappedKey, keyUrlString, err = util.FetchKey("", "")
			if err != nil {
				return errors.Wrap(err, "Error while creating key")
			}
			symKey, err = util.UnwrapKey(wrappedKey, constants.EnvelopePrivatekeyLocation)
			if err != nil {
				return errors.Wrap(err, "Error while unwrapping the key")
			}
		}
	} else if input.Operation == keyprovider.OpKeyUnwrap {
		return errors.Errorf("Operation %v not supported", input.Operation)
	} else {
		return errors.Errorf("Operation %v not recognized", input.Operation)
	}

	// Create wrapped key blob
	wrappedOCIKey, err := aesEncrypt(symKey, input.KeyWrapParams.OptsData)
	if err != nil {
		return errors.Wrap(err, "Error while encrypting key")
	}

	ap := ocicrypt_keyprovider.AnnotationPacket{
		KeyUrl:     keyUrlString,
		WrappedKey: wrappedOCIKey,
		WrapType:   constants.KbsEncryptAlgo,
	}

	jsonString, err := json.Marshal(ap)
	if err != nil {
		return errors.Wrap(err, "Error while serializing Annotation Packet")
	}

	keyProviderOutput := keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyWrapResults: keyprovider.KeyWrapResults{Annotation: jsonString},
	}
	serializedKeyProviderOutput, err := json.Marshal(keyProviderOutput)
	if err != nil {
		return errors.Wrap(err, "Error while serializing KeyProviderKeyWrapProtocolOutput")
	}

	fmt.Println(string(serializedKeyProviderOutput))

	return nil
}
