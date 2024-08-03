package tests

import (
	"reflect"
	"testing"

	. "github.com/rnben/mysql-funcs-go"
)

func TestDesDecrypt(t *testing.T) {
	type args struct {
		encrypted string
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
				encrypted: "/4XOZReziOTR",
			},
			want: "d123456",
		},
		{
			name: "test-02",
			args: args{
				plainKey:  "1234554321",
				encrypted: "/xz9BQ1Ut+OK30k9ll72Nvs=",
			},
			want: "system123456",
		},
		{
			name: "test-03",
			args: args{
				plainKey:  "1234554321",
				encrypted: "",
			},
			want: "",
		},
		{
			name: "test-04",
			args: args{
				plainKey:  "",
				encrypted: "",
			},
			want: "",
		},
		{
			name: "test-05",
			args: args{
				plainKey:  "",
				encrypted: "/x5b4HgjdjYm",
			},
			want: "hello",
		},
		{
			name: "test-06",
			args: args{
				plainKey:  "",
				encrypted: "aGVsbG9oZWxs",
			},
			want:    "",
			wantErr: true, // invalid encrypted text
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encryptedBytes, _ := FromBase64(tt.args.encrypted)
			got, err := DesDecrypt(encryptedBytes, tt.args.plainKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("DESDecrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DesDecrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
