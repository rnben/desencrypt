package tests

import (
	"testing"

	. "github.com/rnben/mysql-funcs-go"
)

func TestDesEncrypt(t *testing.T) {
	type args struct {
		plainText string
		plainKey  string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "test-01",
			args: args{
				plainKey:  "1234554321",
				plainText: "dh123456",
			},
			want: "/wC4kek48EedwPEGVOesNxE=",
		},
		{
			name: "test-02",
			args: args{
				plainKey:  "1234554321",
				plainText: "system123456",
			},
			want: "/xz9BQ1Ut+OK30k9ll72Nvs=",
		},
		{
			name: "test-03",
			args: args{
				plainKey:  "1234554321",
				plainText: "",
			},
			want: "",
		},
		{
			name: "test-04",
			args: args{
				plainKey:  "",
				plainText: "",
			},
			want: "",
		},
		{
			name: "test-05",
			args: args{
				plainKey:  "",
				plainText: "hello",
			},
			want: "/x5b4HgjdjYm",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encryptedBytes, err := DesEncrypt(tt.args.plainText, tt.args.plainKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("DesEncrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
			got := ToBase64(encryptedBytes)
			if got != tt.want {
				t.Errorf("DesEncrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
