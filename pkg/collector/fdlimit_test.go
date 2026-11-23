package collector

import "testing"

func TestParseFDLimit(t *testing.T) {
	const header = "Limit                     Soft Limit           Hard Limit           Units     \n"
	cases := []struct {
		name string
		data string
		want FDLimit
		ok   bool
	}{
		{
			name: "systemd service default",
			data: header +
				"Max cpu time              unlimited            unlimited            seconds   \n" +
				"Max open files            1024                 524288               files     \n" +
				"Max locked memory         8388608              8388608              bytes     \n",
			want: FDLimit{Soft: 1024, Hard: 524288},
			ok:   true,
		},
		{
			name: "unlimited",
			data: header + "Max open files            unlimited            unlimited            files     \n",
			want: FDLimit{Soft: FDLimitUnlimited, Hard: FDLimitUnlimited},
			ok:   true,
		},
		{
			name: "row missing",
			data: header + "Max processes             63432                63432                processes \n",
		},
		{
			name: "row cut short",
			data: header + "Max open files            1024\n",
		},
		{
			name: "garbage value",
			data: header + "Max open files            lots                 524288               files     \n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseFDLimit(tc.data)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("parseFDLimit = %+v, %v; want %+v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}
