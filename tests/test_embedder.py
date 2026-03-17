import pytest
from unittest.mock import MagicMock, patch
from peerwatch.embedder import Embedder, PeerEmbeddings, PeerPreEmbeddings
from peerwatch.parser import NormalisedData


class TestEmbedder:
    @pytest.fixture
    def mock_embeddings_model(self):
        with patch("peerwatch.embedder.OllamaEmbeddings") as mock:
            instance = MagicMock()
            instance.embed_query.return_value = [0.1] * 384
            mock.return_value = instance
            yield instance

    @pytest.fixture
    def sample_normalised_data(self):
        return NormalisedData(
            mac_address="00:11:22:33:44:55",
            ipv4="192.168.1.1",
            ipv6="2001:db8::1",
            os="Linux",
            os_version="5.4",
            distribution="Ubuntu 20.04",
            device_vendor="Dell",
            open_ports=[22, 80, 443],
            services={
                22: "ssh-OpenSSH",
                80: "http-Apache",
                443: "https-nginx",
            },
        )

    def test_embed_returns_peer_embeddings(self, mock_embeddings_model, sample_normalised_data):
        embedder = Embedder("test-model")
        result = embedder.embed(sample_normalised_data)

        assert isinstance(result, PeerEmbeddings)
        assert result.os == [0.1] * 384
        assert result.port_set == [0.1] * 384
        assert result.services == [0.1] * 384
        assert mock_embeddings_model.embed_query.call_count == 3

    def test_embed_formats_os_correctly(self, mock_embeddings_model, sample_normalised_data):
        embedder = Embedder("test-model")
        embedder.embed(sample_normalised_data)

        os_call = mock_embeddings_model.embed_query.call_args_list[0]
        os_input = os_call[0][0]

        assert "Linux" in os_input
        assert "5.4" in os_input
        assert "Ubuntu 20.04" in os_input
        assert "Dell" in os_input

    def test_embed_formats_ports_correctly(self, mock_embeddings_model, sample_normalised_data):
        embedder = Embedder("test-model")
        embedder.embed(sample_normalised_data)

        ports_call = mock_embeddings_model.embed_query.call_args_list[1]
        ports_input = ports_call[0][0]

        assert "22" in ports_input
        assert "80" in ports_input
        assert "443" in ports_input

    def test_embed_formats_services_correctly(self, mock_embeddings_model, sample_normalised_data):
        embedder = Embedder("test-model")
        embedder.embed(sample_normalised_data)

        services_call = mock_embeddings_model.embed_query.call_args_list[2]
        services_input = services_call[0][0]

        assert "port 22 runs ssh server OpenSSH" in services_input
        assert "port 80 runs http server Apache" in services_input

    def test_embed_raises_on_api_failure(self, mock_embeddings_model):
        mock_embeddings_model.embed_query.side_effect = Exception("API error")

        data = NormalisedData(
            mac_address="00:11:22:33:44:55",
            os="Linux",
        )

        embedder = Embedder("test-model")

        with pytest.raises(Exception, match="API error"):
            embedder.embed(data)

    def test_format_service_preembedding_with_product(self):
        with patch("peerwatch.embedder.OllamaEmbeddings") as mock:
            instance = MagicMock()
            mock.return_value = instance

            embedder = Embedder("test-model")
            result = embedder._format_service_preembedding(8080, "http-nginx")

            assert result == "port 8080 runs http server nginx\n"

    def test_format_service_preembedding_no_product(self):
        with patch("peerwatch.embedder.OllamaEmbeddings") as mock:
            instance = MagicMock()
            mock.return_value = instance

            embedder = Embedder("test-model")
            result = embedder._format_service_preembedding(22, "ssh")

            assert result == "port 22 runs ssh service\n"

    def test_format_service_preembedding_empty(self):
        with patch("peerwatch.embedder.OllamaEmbeddings") as mock:
            instance = MagicMock()
            mock.return_value = instance

            embedder = Embedder("test-model")
            result = embedder._format_service_preembedding(0, "")

            assert result == ""

    def test_prep_to_embed_returns_peer_pre_embeddings(self, sample_normalised_data):
        with patch("peerwatch.embedder.OllamaEmbeddings") as mock:
            instance = MagicMock()
            mock.return_value = instance

            embedder = Embedder("test-model")
            result = embedder._prep_to_embed(sample_normalised_data)

            assert isinstance(result, PeerPreEmbeddings)
            assert "Linux" in result.os
            assert "22, 80, 443" in result.port_set
